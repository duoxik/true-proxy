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

const MARKER: u32 = 0x00ff00ff;

pub struct SurfaceProbe {
    samples: [(i32, i32, u32); 2],
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
pub fn mark_owned_surface(hwnd: HWND, scale: f32) -> Result<SurfaceProbe> {
    let (dc, rect) = client(hwnd)?;
    // Sample the static margins away from rounded corners and interactive controls.
    let inset = (10. * scale).round() as i32;
    let points = [
        (inset, (36. * scale).round() as i32),
        (
            rect.right - inset,
            rect.bottom - (80. * scale).round() as i32,
        ),
    ];
    let mut samples = [(0, 0, 0); 2];
    for (sample, (x, y)) in samples.iter_mut().zip(points) {
        ensure!(
            x >= 4 && y >= 4 && x + 4 < rect.right && y + 4 < rect.bottom,
            "Недостаточная область окна"
        );
        let color = unsafe { GetPixel(dc.dc, x, y) };
        ensure!(
            color != u32::MAX && color != MARKER,
            "Недоступен исходный пиксель"
        );
        *sample = (x, y, color);
    }
    let brush = unsafe { CreateSolidBrush(MARKER) };
    ensure!(!brush.is_null(), "Не создана кисть проверки");
    let ok = samples.iter().all(|&(x, y, _)| {
        let marker = RECT {
            left: x - 4,
            top: y - 4,
            right: x + 4,
            bottom: y + 4,
        };
        unsafe { FillRect(dc.dc, &marker, brush) != 0 && GetPixel(dc.dc, x, y) == MARKER }
    });
    unsafe {
        DeleteObject(brush);
    }
    ensure!(ok, "Не удалось поставить метки перерисовки");
    Ok(SurfaceProbe { samples })
}
pub fn verify_owned_surface(hwnd: HWND, probe: &SurfaceProbe) -> Result<()> {
    let (dc, _rect) = client(hwnd)?;
    for &(x, y, expected) in &probe.samples {
        let color = unsafe { GetPixel(dc.dc, x, y) };
        // The full repaint toggles the background by one color step.
        let restored = [0, 8, 16]
            .into_iter()
            .all(|shift| ((color >> shift) & 0xff).abs_diff((expected >> shift) & 0xff) <= 1);
        ensure!(
            color != u32::MAX && color != MARKER && restored,
            "Пиксель ({x}, {y}) не восстановлен: {color:x}, ожидался {expected:x}"
        );
    }
    Ok(())
}
