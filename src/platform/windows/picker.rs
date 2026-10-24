use anyhow::{Result, ensure};
use windows_sys::Win32::UI::{Controls::Dialogs::*, Input::KeyboardAndMouse::GetActiveWindow};

/// Native modal picker on the UI thread. No shell, CWD change or recent-file entry.
pub fn choose_executable() -> Result<Option<String>> {
    let mut buffer = vec![0u16; 32768];
    let mut dialog = OPENFILENAMEW {
        lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: unsafe { GetActiveWindow() },
        lpstrFilter: windows_sys::core::w!("Исполняемые файлы (*.exe)\0*.exe\0\0"),
        lpstrFile: buffer.as_mut_ptr(),
        nMaxFile: buffer.len() as u32,
        lpstrTitle: windows_sys::core::w!("Выберите приложение"),
        Flags: OFN_EXPLORER
            | OFN_FILEMUSTEXIST
            | OFN_PATHMUSTEXIST
            | OFN_NOCHANGEDIR
            | OFN_DONTADDTORECENT,
        ..Default::default()
    };
    // The buffer/filter and owner window remain live for the modal call.
    if unsafe { GetOpenFileNameW(&mut dialog) } == 0 {
        let error = unsafe { CommDlgExtendedError() };
        ensure!(error == 0, "Не удалось выбрать файл ({error})");
        return Ok(None);
    }
    let end = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
    let path = String::from_utf16(&buffer[..end])?;
    ensure!(
        std::path::Path::new(&path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("exe")),
        "Выберите исполняемый файл .exe"
    );
    Ok(Some(path))
}
