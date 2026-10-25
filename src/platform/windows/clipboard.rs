//! CF_UNICODETEXT ownership stays with Windows only after SetClipboardData succeeds.
use anyhow::{Result, ensure};
use windows_sys::Win32::{
    Foundation::{GlobalFree, HWND},
    System::{
        DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData},
        Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock},
        Threading::GetCurrentProcessId,
    },
    UI::WindowsAndMessaging::GetWindowThreadProcessId,
};

struct Clipboard;
impl Drop for Clipboard {
    fn drop(&mut self) {
        unsafe {
            CloseClipboard();
        }
    }
}
struct Allocation(windows_sys::Win32::Foundation::HGLOBAL);
impl Drop for Allocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                GlobalFree(self.0);
            }
        }
    }
}

pub fn copy(owner: usize, text: &str) -> Result<()> {
    let owner = owner as HWND;
    let mut pid = 0;
    unsafe {
        GetWindowThreadProcessId(owner, &mut pid);
    }
    ensure!(
        !owner.is_null() && pid == unsafe { GetCurrentProcessId() } && !text.contains('\0'),
        "Не удалось подготовить текст для буфера"
    );
    let wide: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
    let mut allocation = Allocation(unsafe { GlobalAlloc(GMEM_MOVEABLE, wide.len() * 2) });
    ensure!(
        !allocation.0.is_null(),
        "Недостаточно памяти для буфера обмена"
    );
    let pointer = unsafe { GlobalLock(allocation.0) };
    ensure!(!pointer.is_null(), "Не удалось открыть память буфера");
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), pointer.cast::<u16>(), wide.len());
        GlobalUnlock(allocation.0);
    }
    ensure!(
        unsafe { OpenClipboard(owner) } != 0,
        "Буфер обмена занят. Повторите экспорт."
    );
    let _clipboard = Clipboard;
    ensure!(
        unsafe { EmptyClipboard() } != 0,
        "Не удалось очистить буфер обмена"
    );
    ensure!(
        !unsafe { SetClipboardData(13, allocation.0) }.is_null(),
        "Не удалось скопировать конфигурацию"
    );
    allocation.0 = std::ptr::null_mut();
    Ok(())
}
