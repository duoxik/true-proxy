//! Per-user interactive logon task. No passwords, shell commands or service.
//! Only an explicit UI checkbox creates/deletes our own SID-scoped task.
use anyhow::{Context, Result, ensure};
use std::{path::Path, ptr};
use windows::{
    Win32::System::{
        Com::{
            CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
            CoUninitialize,
        },
        TaskScheduler::{
            IRegisteredTask, ITaskFolder, ITaskService, TASK_CREATE_OR_UPDATE,
            TASK_LOGON_INTERACTIVE_TOKEN, TaskScheduler,
        },
        Variant::VARIANT,
    },
    core::BSTR,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, LocalFree},
    Security::{
        Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

const SOURCE: &str = "TrueProxy.Desktop.Autostart.v1";
struct Com;
impl Drop for Com {
    fn drop(&mut self) {
        unsafe {
            CoUninitialize();
        }
    }
}
struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Local(*mut u16);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0.cast());
        }
    }
}

fn user_sid() -> Result<String> {
    let mut token = ptr::null_mut();
    // SAFETY: query-only token, aligned backing storage remains live while SID
    // is converted. The OS-allocated SID string and token have owned RAII guards.
    ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
        "Не удалось определить пользователя автозапуска"
    );
    let token = Token(token);
    let mut size = 0;
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut size);
    }
    ensure!(
        (std::mem::size_of::<TOKEN_USER>() as u32..=65536).contains(&size),
        "Некорректный размер токена пользователя"
    );
    let mut storage = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    ensure!(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                storage.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        } != 0,
        "Не удалось прочитать пользователя автозапуска"
    );
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    let mut text = ptr::null_mut();
    ensure!(
        unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } != 0,
        "Не удалось прочитать SID пользователя"
    );
    let text = Local(text);
    let mut length = 0;
    while length < 256 && unsafe { *text.0.add(length) } != 0 {
        length += 1;
    }
    ensure!(length < 256, "Слишком длинный SID пользователя");
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(text.0, length) })?;
    ensure!(
        sid.starts_with("S-1-")
            && sid
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'S' || byte == b'-'),
        "Некорректный SID пользователя"
    );
    Ok(sid)
}

struct Scheduler {
    _service: ITaskService,
    folder: ITaskFolder,
    _com: Com,
}
impl Scheduler {
    fn connect() -> Result<Self> {
        // Called on the control worker, not Slint's UI apartment. COM interfaces
        // are dropped on this same thread before CoUninitialize.
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
        }
        let com = Com;
        let service: ITaskService =
            unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)? };
        let empty = VARIANT::default();
        unsafe {
            service.Connect(&empty, &empty, &empty, &empty)?;
        }
        let folder = unsafe { service.GetFolder(&BSTR::from("\\"))? };
        Ok(Self {
            _service: service,
            folder,
            _com: com,
        })
    }
    fn task(&self, name: &str) -> Result<Option<IRegisteredTask>> {
        let task = match unsafe { self.folder.GetTask(&BSTR::from(name)) } {
            Ok(task) => task,
            Err(error) if error.code().0 as u32 == 0x80070002 => return Ok(None),
            Err(error) => return Err(error).context("Не удалось прочитать задачу автозапуска"),
        };
        let definition = unsafe { task.Definition()? };
        let mut source = BSTR::new();
        unsafe {
            definition.RegistrationInfo()?.Source(&mut source)?;
        }
        ensure!(
            source == SOURCE,
            "Задача с этим именем не принадлежит True Proxy; изменение отменено"
        );
        Ok(Some(task))
    }
}

fn task_name(sid: &str) -> String {
    format!("TrueProxy.Autostart.{sid}")
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn task_xml(executable: &Path, sid: &str) -> Result<String> {
    ensure!(
        executable.is_absolute(),
        "Путь автозапуска должен быть абсолютным"
    );
    let exe = escape(
        executable
            .to_str()
            .context("Не удалось преобразовать путь автозапуска")?,
    );
    let directory = escape(
        executable
            .parent()
            .and_then(Path::to_str)
            .context("Не найдена папка программы")?,
    );
    let sid = escape(sid);
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
 <RegistrationInfo><Description>True Proxy: запуск при входе пользователя</Description><Source>{SOURCE}</Source></RegistrationInfo>
 <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{sid}</UserId></LogonTrigger></Triggers>
 <Principals><Principal id="User"><UserId>{sid}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
 <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><Enabled>true</Enabled><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
 <Actions Context="User"><Exec><Command>{exe}</Command><Arguments>--tray</Arguments><WorkingDirectory>{directory}</WorkingDirectory></Exec></Actions>
</Task>"#
    ))
}

pub fn autostart_enabled() -> Result<bool> {
    let scheduler = Scheduler::connect()?;
    let task = scheduler.task(&task_name(&user_sid()?))?;
    task.map(|task| {
        unsafe { task.Enabled() }
            .map(|enabled| enabled.0 != 0)
            .map_err(Into::into)
    })
    .transpose()
    .map(|enabled| enabled.unwrap_or(false))
}

pub fn set_autostart(enabled: bool) -> Result<bool> {
    ensure!(
        super::is_admin(),
        "Изменение автозапуска требует прав администратора"
    );
    let scheduler = Scheduler::connect()?;
    let sid = user_sid()?;
    let name = task_name(&sid);
    let existing = scheduler.task(&name)?;
    if enabled {
        let xml = task_xml(&std::env::current_exe()?, &sid)?;
        let empty = VARIANT::default();
        unsafe {
            scheduler.folder.RegisterTask(
                &BSTR::from(&name),
                &BSTR::from(xml),
                TASK_CREATE_OR_UPDATE.0,
                &empty,
                &empty,
                TASK_LOGON_INTERACTIVE_TOKEN,
                &empty,
            )?;
        }
    } else if existing.is_some() {
        unsafe {
            scheduler.folder.DeleteTask(&BSTR::from(name), 0)?;
        }
    }
    autostart_enabled()
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::{Win32::System::TaskScheduler::IExecAction, core::Interface};
    #[test]
    fn logon_xml_is_valid_and_preserves_unicode_path_without_enabling_proxy() {
        let scheduler = Scheduler::connect().unwrap();
        let sid = user_sid().unwrap();
        let path = Path::new(r"C:\Программы\True & Proxy\TrueProxy.exe");
        let xml = task_xml(path, &sid).unwrap();
        assert!(!xml.contains("--enable"));
        assert!(!xml.contains("--paused"));
        assert!(xml.contains("HighestAvailable") && xml.contains("InteractiveToken"));
        let definition = unsafe { scheduler._service.NewTask(0).unwrap() };
        // In-memory parsing only: no task registration, login trigger or startup change.
        unsafe {
            definition.SetXmlText(&BSTR::from(xml)).unwrap();
            let action: IExecAction = definition
                .Actions()
                .unwrap()
                .get_Item(1)
                .unwrap()
                .cast()
                .unwrap();
            let mut actual = BSTR::new();
            action.Path(&mut actual).unwrap();
            assert_eq!(actual.to_string(), path.to_str().unwrap());
            let mut arguments = BSTR::new();
            action.Arguments(&mut arguments).unwrap();
            assert_eq!(arguments, BSTR::from("--tray"));
        }
    }
}
