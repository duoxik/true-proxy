//! Isolated UI diagnostic. Only the current process's own visible client area
//! can be marked/read; callers use it exclusively in the --smoke-ui fixture.
use anyhow::{Result, bail, ensure};
use windows_sys::Win32::{
    Foundation::{HWND, RECT},
    Graphics::Gdi::{
        CreateSolidBrush, DeleteObject, FillRect, GetClipBox, GetDC, GetPixel, NULLREGION,
        ReleaseDC,
    },
    System::Threading::GetCurrentProcessId,
    UI::WindowsAndMessaging::{GetClientRect, GetWindowThreadProcessId, IsWindowVisible},
};
struct Dc {
    hwnd: HWND,
    dc: windows_sys::Win32::Graphics::Gdi::HDC,
}

const MARKER: u32 = 0x00ff00ff;
const PROBE_RADIUS: i32 = 4;

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
        "The repaint probe requires a visible window owned by this process"
    );
    let mut rect = RECT::default();
    ensure!(
        unsafe { GetClientRect(hwnd, &mut rect) } != 0 && rect.right > 20 && rect.bottom > 20,
        "The repaint probe requires a nonempty client area"
    );
    let dc = unsafe { GetDC(hwnd) };
    ensure!(!dc.is_null(), "Could not access the window surface");
    Ok((Dc { hwnd, dc }, rect))
}
pub fn mark_owned_surface(hwnd: HWND, scale: f32) -> Result<SurfaceProbe> {
    let (dc, rect) = client(hwnd)?;
    let mut clip = RECT::default();
    let region = unsafe { GetClipBox(dc.dc, &mut clip) };
    ensure!(
        region > NULLREGION,
        "No visible client region for the repaint probe ({region})"
    );
    let left = clip.left.max(rect.left) + PROBE_RADIUS;
    let top = clip.top.max(rect.top) + PROBE_RADIUS;
    let right = clip.right.min(rect.right) - PROBE_RADIUS;
    let bottom = clip.bottom.min(rect.bottom) - PROBE_RADIUS;
    ensure!(
        left <= right && top <= bottom,
        "Visible client area is too small for repaint probes ({left}, {top})–({right}, {bottom})"
    );

    // Prefer static margins. A complex clip region can still hide points inside its bounds.
    let inset = (10. * scale).round() as i32;
    let center_x = left + (right - left) / 2;
    let center_y = top + (bottom - top) / 2;
    let clamp = |x: i32, y: i32| (x.clamp(left, right), y.clamp(top, bottom));
    let candidates = [
        clamp(inset, (36. * scale).round() as i32),
        clamp(
            rect.right - inset,
            rect.bottom - (80. * scale).round() as i32,
        ),
    ]
    .into_iter()
    .chain(
        [center_x, right, left]
            .into_iter()
            .flat_map(|x| [center_y, bottom, top].into_iter().map(move |y| (x, y))),
    );
    let mut samples = [(0_i32, 0_i32, 0_u32); 2];
    let mut count = 0;
    let diameter = (2 * PROBE_RADIUS) as u32;
    for (x, y) in candidates {
        let (first_x, first_y, _) = samples[0];
        if count != 0 && x.abs_diff(first_x) < diameter && y.abs_diff(first_y) < diameter {
            continue;
        }
        let color = unsafe { GetPixel(dc.dc, x, y) };
        if color != u32::MAX && color != MARKER {
            samples[count] = (x, y, color);
            count += 1;
            if count == samples.len() {
                break;
            }
        }
    }
    ensure!(
        count == samples.len(),
        "Found {count} of two readable repaint probe points in client bounds ({left}, {top})–({right}, {bottom})"
    );

    let brush = unsafe { CreateSolidBrush(MARKER) };
    ensure!(!brush.is_null(), "Could not create the repaint probe brush");
    let failed = samples.iter().find(|&&(x, y, _)| {
        let marker = RECT {
            left: x - PROBE_RADIUS,
            top: y - PROBE_RADIUS,
            right: x + PROBE_RADIUS,
            bottom: y + PROBE_RADIUS,
        };
        unsafe { FillRect(dc.dc, &marker, brush) == 0 || GetPixel(dc.dc, x, y) != MARKER }
    });
    unsafe {
        DeleteObject(brush);
    }
    if let Some(&(x, y, _)) = failed {
        bail!("Could not mark repaint probe pixel ({x}, {y})");
    }
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
            "Repaint probe pixel ({x}, {y}) was not restored. Read {color:06x}, expected {expected:06x}"
        );
    }
    Ok(())
}
