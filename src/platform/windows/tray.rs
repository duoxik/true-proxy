//! Windows notification icon with explicit registration recovery.
//! All handles and callbacks belong to the UI thread. The boxed State outlives
//! its HWND; USERDATA is cleared before destroying the window and its icons.
use anyhow::{Context, Result, ensure};
use std::{
    cell::{Cell, RefCell},
    ptr,
    rc::Rc,
};
use windows_sys::{
    Win32::{
        Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM},
        Graphics::Gdi::{
            BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateBitmap, CreateDIBSection, DIB_RGB_COLORS,
            DeleteObject,
        },
        System::LibraryLoader::GetModuleHandleW,
        UI::{
            Shell::{
                NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
                Shell_NotifyIconW,
            },
            WindowsAndMessaging::*,
        },
    },
    core::w,
};

const CLASS: *const u16 = w!("TrueProxy.Tray.v2");
const PREVIEW_CLASS: *const u16 = w!("TrueProxy.Tray.Preview.v2");
const ICON_MESSAGE: u32 = WM_APP + 21;
const OPEN_MESSAGE: u32 = WM_APP + 22;
const RETRY: usize = 1;
const ICON_ID: u32 = 1;
type Callback = Rc<dyn Fn()>;
type Notify = Box<dyn Fn(u32, &NOTIFYICONDATAW) -> bool>;

struct Icon(HICON);
impl Drop for Icon {
    fn drop(&mut self) {
        unsafe {
            DestroyIcon(self.0);
        }
    }
}
struct Bitmap(windows_sys::Win32::Graphics::Gdi::HBITMAP);
impl Drop for Bitmap {
    fn drop(&mut self) {
        unsafe {
            DeleteObject(self.0);
        }
    }
}

fn icon(active: bool) -> Result<Icon> {
    let size = 32;
    let rgba = crate::branding::rgba(size, Some(active));
    let info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: size as i32,
            biHeight: -(size as i32),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut bits = ptr::null_mut();
    let color = Bitmap(unsafe {
        CreateDIBSection(
            ptr::null_mut(),
            &info,
            DIB_RGB_COLORS,
            &mut bits,
            ptr::null_mut(),
            0,
        )
    });
    ensure!(
        !color.0.is_null() && !bits.is_null(),
        "Не удалось создать изображение трея"
    );
    // SAFETY: the DIB owns size*size BGRA pixels; both bitmaps remain live until
    // CreateIconIndirect copies their data. The resulting HICON has its own RAII guard.
    let destination = unsafe { std::slice::from_raw_parts_mut(bits.cast::<u8>(), rgba.len()) };
    for (source, target) in rgba
        .as_chunks::<4>()
        .0
        .iter()
        .zip(destination.as_chunks_mut::<4>().0.iter_mut())
    {
        target.copy_from_slice(&[source[2], source[1], source[0], source[3]]);
    }
    let mask = Bitmap(unsafe { CreateBitmap(size as i32, size as i32, 1, 1, ptr::null()) });
    ensure!(!mask.0.is_null(), "Не удалось создать маску трея");
    let handle = unsafe {
        CreateIconIndirect(&ICONINFO {
            fIcon: 1,
            xHotspot: 0,
            yHotspot: 0,
            hbmMask: mask.0,
            hbmColor: color.0,
        })
    };
    ensure!(!handle.is_null(), "Не удалось создать значок трея");
    Ok(Icon(handle))
}

struct State {
    hwnd: Cell<HWND>,
    icons: [Icon; 2],
    active: Cell<bool>,
    status: RefCell<String>,
    registered: Cell<bool>,
    retrying: Cell<bool>,
    taskbar_message: u32,
    notify: Notify,
    callbacks: RefCell<[Option<Callback>; 3]>,
}
impl State {
    fn data(&self) -> NOTIFYICONDATAW {
        // HWND + fixed ID supports a portable unsigned EXE moved between folders.
        // A fixed NIF_GUID would bind registration to its original binary path.
        let mut data = NOTIFYICONDATAW {
            cbSize: size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: self.hwnd.get(),
            uID: ICON_ID,
            uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
            uCallbackMessage: ICON_MESSAGE,
            hIcon: self.icons[usize::from(self.active.get())].0,
            ..Default::default()
        };
        let tip = format!("True Proxy · {}", self.status.borrow());
        // Keep the terminator, and don't split a UTF-16 surrogate pair.
        let mut tip = tip
            .encode_utf16()
            .take(data.szTip.len() - 1)
            .collect::<Vec<_>>();
        if tip.last().is_some_and(|c| (0xd800..=0xdbff).contains(c)) {
            tip.pop();
        }
        data.szTip[..tip.len()].copy_from_slice(&tip);
        data
    }
    fn register(&self) -> Result<()> {
        // A DPI-change TaskbarCreated can arrive while the icon still exists.
        if (self.notify)(NIM_ADD, &self.data()) || (self.notify)(NIM_MODIFY, &self.data()) {
            self.registered.set(true);
            unsafe {
                KillTimer(self.hwnd.get(), RETRY);
            }
            self.retrying.set(false);
        } else {
            self.registered.set(false);
            if !self.retrying.get() {
                ensure!(
                    unsafe { SetTimer(self.hwnd.get(), RETRY, 2000, None) } != 0,
                    "Не удалось запустить восстановление трея"
                );
                self.retrying.set(true);
            }
        }
        Ok(())
    }
    fn dispatch(&self, action: usize) {
        let callback = self.callbacks.borrow().get(action).cloned().flatten();
        if let Some(callback) = callback {
            callback();
        }
    }
    fn menu(&self) {
        let menu = unsafe { CreatePopupMenu() };
        if menu.is_null() {
            return;
        }
        let pause = if self.active.get() {
            w!("Приостановить")
        } else {
            w!("Включить")
        };
        unsafe {
            AppendMenuW(menu, MF_STRING, 1, w!("Открыть True Proxy"));
            AppendMenuW(menu, MF_STRING, 2, pause);
            AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
            AppendMenuW(menu, MF_STRING, 3, w!("Выход"));
        }
        let mut point = POINT::default();
        let action = unsafe {
            GetCursorPos(&mut point);
            SetForegroundWindow(self.hwnd.get());
            TrackPopupMenu(
                menu,
                TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
                point.x,
                point.y,
                0,
                self.hwnd.get(),
                ptr::null(),
            )
        };
        unsafe {
            DestroyMenu(menu);
            PostMessageW(self.hwnd.get(), WM_NULL, 0, 0);
        }
        if (1..=3).contains(&action) {
            self.dispatch(action as usize - 1);
        }
    }
}

pub struct Tray {
    state: Box<State>,
}
impl Tray {
    pub fn new(preview: bool) -> Result<Self> {
        Self::with_notify(
            preview,
            Box::new(|message, data| unsafe { Shell_NotifyIconW(message, data) != 0 }),
        )
    }
    fn with_notify(preview: bool, notify: Notify) -> Result<Self> {
        let module = unsafe { GetModuleHandleW(ptr::null()) };
        ensure!(!module.is_null(), "Не удалось получить модуль трея");
        let class = if preview { PREVIEW_CLASS } else { CLASS };
        let definition = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: module,
            lpszClassName: class,
            ..Default::default()
        };
        // RegisterClass can report an already registered class in UI tests.
        unsafe {
            RegisterClassW(&definition);
        }
        let taskbar_message = unsafe { RegisterWindowMessageW(w!("TaskbarCreated")) };
        ensure!(
            taskbar_message != 0,
            "Не удалось подписаться на восстановление панели задач"
        );
        let state = Box::new(State {
            hwnd: Cell::new(ptr::null_mut()),
            icons: [icon(false)?, icon(true)?],
            active: Cell::new(false),
            status: RefCell::new("Запуск…".into()),
            registered: Cell::new(false),
            retrying: Cell::new(false),
            taskbar_message,
            notify,
            callbacks: RefCell::new([None, None, None]),
        });
        // A hidden TOP-LEVEL tool window receives TaskbarCreated broadcasts.
        // HWND_MESSAGE cannot receive those broadcasts. No WS_VISIBLE is used.
        let hwnd = unsafe {
            CreateWindowExW(
                WS_EX_TOOLWINDOW,
                class,
                w!("True Proxy tray"),
                WS_POPUP,
                0,
                0,
                0,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                module,
                ptr::null(),
            )
        };
        ensure!(!hwnd.is_null(), "Не удалось создать окно трея");
        state.hwnd.set(hwnd);
        unsafe {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, &*state as *const State as isize);
        }
        let tray = Self { state };
        // Explorer normally runs below our elevated integrity level. Allow only
        // shell notifications and the harmless open-window request for this HWND.
        for message in [taskbar_message, ICON_MESSAGE, OPEN_MESSAGE] {
            ensure!(
                unsafe {
                    ChangeWindowMessageFilterEx(hwnd, message, MSGFLT_ALLOW, ptr::null_mut())
                } != 0,
                "Не удалось настроить сообщения трея"
            );
        }
        tray.state
            .register()
            .context("Не удалось восстановить значок трея")?;
        Ok(tray)
    }
    pub fn update(&self, active: bool, status: &str) {
        self.state.active.set(active);
        *self.state.status.borrow_mut() = status.into();
        if (!self.state.registered.get() || !(self.state.notify)(NIM_MODIFY, &self.state.data()))
            && self.state.register().is_err()
        {
            self.state.dispatch(0);
        }
    }
    pub fn on_open(&self, callback: impl Fn() + 'static) {
        self.state.callbacks.borrow_mut()[0] = Some(Rc::new(callback));
    }
    pub fn on_toggle(&self, callback: impl Fn() + 'static) {
        self.state.callbacks.borrow_mut()[1] = Some(Rc::new(callback));
    }
    pub fn on_exit(&self, callback: impl Fn() + 'static) {
        self.state.callbacks.borrow_mut()[2] = Some(Rc::new(callback));
    }
    pub fn invoke_open(&self) {
        unsafe {
            PostMessageW(self.state.hwnd.get(), OPEN_MESSAGE, 0, 0);
        }
    }
    pub fn registered(&self) -> bool {
        self.state.registered.get()
    }
}
impl Drop for Tray {
    fn drop(&mut self) {
        let hwnd = self.state.hwnd.get();
        unsafe {
            KillTimer(hwnd, RETRY);
            (self.state.notify)(NIM_DELETE, &self.state.data());
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            DestroyWindow(hwnd);
        }
    }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // USERDATA is installed only after State is boxed, and cleared before Drop.
    // All access, Win32 callbacks and destruction stay on the creating UI thread.
    let state = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const State;
    if !state.is_null() {
        let state = unsafe { &*state };
        let handled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if message == state.taskbar_message || (message == WM_TIMER && wparam == RETRY) {
                if message == WM_TIMER && state.registered.get() {
                    return true;
                }
                if message == state.taskbar_message {
                    state.registered.set(false);
                }
                if state.register().is_err() {
                    state.dispatch(0);
                }
            } else if message == OPEN_MESSAGE {
                state.dispatch(0);
            } else if message == ICON_MESSAGE && wparam as u32 == ICON_ID {
                match lparam as u32 {
                    WM_LBUTTONUP => state.dispatch(0),
                    WM_RBUTTONUP | WM_CONTEXTMENU => state.menu(),
                    _ => {}
                }
            } else {
                return false;
            }
            true
        }))
        .unwrap_or(false);
        if handled {
            return 0;
        }
    }
    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}

/// A second launch only asks the existing desktop instance to open its window.
pub fn activate_existing() -> bool {
    let hwnd = unsafe { FindWindowW(CLASS, ptr::null()) };
    !hwnd.is_null() && unsafe { PostMessageW(hwnd, OPEN_MESSAGE, 0, 0) } != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn early_logon_retries_then_stops_and_recovers_only_its_own_icon() {
        let ready = Rc::new(Cell::new(false));
        let calls = Rc::new(RefCell::new(Vec::new()));
        let status = Rc::new(RefCell::new(String::new()));
        let (available, history, last_tip) = (ready.clone(), calls.clone(), status.clone());
        let tray = Tray::with_notify(
            true,
            Box::new(move |message, data| {
                history.borrow_mut().push(message);
                let end = data.szTip.iter().position(|c| *c == 0).unwrap();
                *last_tip.borrow_mut() = String::from_utf16(&data.szTip[..end]).unwrap();
                available.get()
            }),
        )
        .unwrap();
        assert!(!tray.registered());
        assert!(tray.state.retrying.get());
        let hwnd = tray.state.hwnd.get();
        // Enumerate without modifying other windows: message-only windows are absent.
        unsafe extern "system" fn find(hwnd: HWND, parameter: LPARAM) -> i32 {
            let result = unsafe { &mut *(parameter as *mut (HWND, bool)) };
            if hwnd == result.0 {
                result.1 = true;
            }
            1
        }
        let mut found = (hwnd, false);
        unsafe {
            EnumWindows(Some(find), &mut found as *mut _ as LPARAM);
        }
        assert!(found.1, "The listener must receive top-level broadcasts");
        tray.update(true, "Проверка: включено");
        ready.set(true);
        unsafe {
            SendMessageW(hwnd, WM_TIMER, RETRY, 0);
        }
        assert!(tray.registered());
        assert!(!tray.state.retrying.get());
        assert!(status.borrow().contains("Проверка: включено"));
        let count = calls.borrow().len();
        unsafe {
            SendMessageW(hwnd, WM_TIMER, RETRY, 0);
        }
        assert_eq!(
            calls.borrow().len(),
            count,
            "No polling once registration succeeds"
        );
        ready.set(false);
        unsafe {
            SendMessageW(hwnd, tray.state.taskbar_message, 0, 0);
        }
        assert!(!tray.registered());
        assert!(tray.state.retrying.get());
        ready.set(true);
        unsafe {
            SendMessageW(hwnd, WM_TIMER, RETRY, 0);
        }
        assert!(tray.registered());
        assert!(!tray.state.retrying.get());
        let opens = Rc::new(Cell::new(0));
        let counter = opens.clone();
        tray.on_open(move || counter.set(counter.get() + 1));
        unsafe {
            SendMessageW(hwnd, OPEN_MESSAGE, 0, 0);
        }
        assert_eq!(
            opens.get(),
            1,
            "Second launch must be able to reopen the window"
        );
        let events = Rc::new(RefCell::new(Vec::new()));
        let event = events.clone();
        tray.on_toggle(move || event.borrow_mut().push("toggle"));
        let event = events.clone();
        tray.on_exit(move || event.borrow_mut().push("exit"));
        tray.state.dispatch(1);
        tray.state.dispatch(2);
        assert_eq!(&*events.borrow(), &["toggle", "exit"]);
        drop(tray);
        assert_eq!(calls.borrow().last(), Some(&NIM_DELETE));
        assert_eq!(unsafe { IsWindow(hwnd) }, 0);
    }
}
