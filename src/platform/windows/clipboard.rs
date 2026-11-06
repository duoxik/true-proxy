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
        "Could not prepare text for the clipboard"
    );
    let wide: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
    let mut allocation = Allocation(unsafe { GlobalAlloc(GMEM_MOVEABLE, wide.len() * 2) });
    ensure!(
        !allocation.0.is_null(),
        "Insufficient memory for the clipboard"
    );
    let pointer = unsafe { GlobalLock(allocation.0) };
    ensure!(!pointer.is_null(), "Could not access clipboard memory");
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), pointer.cast::<u16>(), wide.len());
        GlobalUnlock(allocation.0);
    }
    ensure!(
        unsafe { OpenClipboard(owner) } != 0,
        "The clipboard is busy. Try exporting again."
    );
    let _clipboard = Clipboard;
    ensure!(
        unsafe { EmptyClipboard() } != 0,
        "Could not clear the clipboard"
    );
    ensure!(
        !unsafe { SetClipboardData(13, allocation.0) }.is_null(),
        "Could not copy the configuration"
    );
    allocation.0 = std::ptr::null_mut();
    Ok(())
}
