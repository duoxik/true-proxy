//! Isolated UI diagnostic. Only the current process's own visible client area
//! can be marked/read; callers use it exclusively in the --smoke-ui fixture.
use anyhow::{Result, ensure};
use windows_sys::Win32::{
    Foundation::{HWND, RECT},
    Graphics::Gdi::{CreateSolidBrush, DeleteObject, FillRect, GetDC, GetPixel, ReleaseDC},
    System::Threading::GetCurrentProcessId,
    UI::WindowsAndMessaging::{GetClientRect, GetWindowThreadProcessId, IsWindowVisible},
};
struct Dc {
    hwnd: HWND,
    dc: windows_sys::Win32::Graphics::Gdi::HDC,
}
impl Drop for Dc {
    fn drop(&mut self) {
        unsafe {
            ReleaseDC(self.hwnd, self.dc);
        }
    }
}
fn client(hwnd: HWND) -> Result<(Dc, RECT)> {
    let mut pid = 0;
    unsafe {
        GetWindowThreadProcessId(hwnd, &mut pid);
    }
    ensure!(
        pid == unsafe { GetCurrentProcessId() } && unsafe { IsWindowVisible(hwnd) } != 0,
        "Проверка разрешена только для своего видимого окна"
    );
    let mut rect = RECT::default();
    ensure!(
        unsafe { GetClientRect(hwnd, &mut rect) } != 0 && rect.right > 20 && rect.bottom > 20,
        "Пустая область окна"
    );
    let dc = unsafe { GetDC(hwnd) };
    ensure!(!dc.is_null(), "Недоступна поверхность окна");
    Ok((Dc { hwnd, dc }, rect))
}
pub fn mark_owned_surface(hwnd: HWND, scale: f32) -> Result<()> {
    let (dc, rect) = client(hwnd)?;
    // Two distant static areas expose a stale partial-render buffer without
    // capturing any other app or changing the user's Explorer/display setup.
    let first = RECT {
        left: 1,
        top: 1,
        right: 9,
        bottom: 9,
    };
    let x = (220. * scale) as i32;
    let y = (120. * scale) as i32;
    ensure!(
        x + 4 < rect.right && y + 4 < rect.bottom,
        "Недостаточная область окна"
    );
    let last = RECT {
        left: x - 4,
        top: y - 4,
        right: x + 4,
        bottom: y + 4,
    };
    let brush = unsafe { CreateSolidBrush(0x00ff00ff) };
    ensure!(!brush.is_null(), "Не создана кисть проверки");
    let ok = unsafe { FillRect(dc.dc, &first, brush) != 0 && FillRect(dc.dc, &last, brush) != 0 };
    unsafe {
        DeleteObject(brush);
    }
    ensure!(ok, "Не удалось поставить метки перерисовки");
    Ok(())
}
pub fn verify_owned_surface(hwnd: HWND, scale: f32) -> Result<()> {
    let (dc, _rect) = client(hwnd)?;
    let sidebar = unsafe { GetPixel(dc.dc, 4, 4) };
    let background = unsafe { GetPixel(dc.dc, (220. * scale) as i32, (120. * scale) as i32) };
    ensure!(
        sidebar == 0x001e1614,
        "Статичная панель не перерисована: {sidebar:x}"
    );
    ensure!(
        matches!(background, 0x00181210 | 0x00191210),
        "Фон окна не восстановлен: {background:x}"
    );
    Ok(())
}
