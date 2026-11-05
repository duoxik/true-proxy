//! Geometry and focus queries for the tray popup. No Slint dependency and no
//! polling: the application decides when to show or hide its own window.
use windows_sys::Win32::{
    Foundation::{HWND, POINT, RECT},
    Graphics::Gdi::{GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromRect},
    UI::{
        HiDpi::{GetDpiForMonitor, GetDpiForWindow, MDT_EFFECTIVE_DPI},
        Shell::{NOTIFYICONIDENTIFIER, Shell_NotifyIconGetRect},
        WindowsAndMessaging::{
            GW_OWNER, GetCursorPos, GetForegroundWindow, GetWindow, GetWindowThreadProcessId,
        },
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PopupGeometry {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

/// All arguments and results are physical screen pixels, including negative
/// monitor coordinates. Oversized requests shrink to the monitor's work area.
pub fn placement(width: u32, height: u32, anchor: RECT, work: RECT) -> Option<PopupGeometry> {
    let (left, top, right, bottom) = (
        i64::from(work.left),
        i64::from(work.top),
        i64::from(work.right),
        i64::from(work.bottom),
    );
    if width == 0
        || height == 0
        || right <= left
        || bottom <= top
        || anchor.right < anchor.left
        || anchor.bottom < anchor.top
    {
        return None;
    }
    let width = i64::from(width).min(right - left);
    let height = i64::from(height).min(bottom - top);
    let gap = 8;
    let mut x = i64::from(anchor.right) - width;
    let mut y = i64::from(anchor.top) - height - gap;
    if i64::from(anchor.bottom) <= top {
        // Taskbar at the top.
        y = top + gap;
    } else if i64::from(anchor.top) >= bottom {
        // Taskbar at the bottom.
        y = bottom - height - gap;
    } else if i64::from(anchor.right) <= left {
        // Taskbar at the left.
        x = left + gap;
        y = i64::from(anchor.bottom) - height;
    } else if i64::from(anchor.left) >= right {
        // Taskbar at the right.
        x = right - width - gap;
        y = i64::from(anchor.bottom) - height;
    } else if y < top && i64::from(anchor.bottom) + gap + height <= bottom {
        // Overflow popup or cursor fallback inside the work area.
        y = i64::from(anchor.bottom) + gap;
    }
    Some(PopupGeometry {
        x: x.clamp(left, right - width) as i32,
        y: y.clamp(top, bottom - height) as i32,
        width: width as u32,
        height: height as u32,
    })
}

fn physical_size(width: u32, height: u32, dpi_x: u32, dpi_y: u32) -> (u32, u32) {
    let scale = |logical: u32, dpi: u32| {
        ((u64::from(logical) * u64::from(dpi.max(1)) + 48) / 96).min(u64::from(u32::MAX)) as u32
    };
    (scale(width, dpi_x), scale(height, dpi_y))
}

pub(crate) fn from_tray(
    hwnd: HWND,
    icon_id: u32,
    logical_width: u32,
    logical_height: u32,
) -> Option<PopupGeometry> {
    let identity = NOTIFYICONIDENTIFIER {
        cbSize: size_of::<NOTIFYICONIDENTIFIER>() as u32,
        hWnd: hwnd,
        uID: icon_id,
        ..Default::default()
    };
    let mut anchor = RECT::default();
    // SAFETY: the fixed identity addresses only this process's tray icon; both
    // structs remain live for the Shell call. A hidden/overflow icon may fail.
    if unsafe { Shell_NotifyIconGetRect(&identity, &mut anchor) } < 0
        || anchor.right <= anchor.left
        || anchor.bottom <= anchor.top
    {
        let mut cursor = POINT::default();
        if unsafe { GetCursorPos(&mut cursor) } == 0 {
            return None;
        }
        anchor = RECT {
            left: cursor.x,
            top: cursor.y,
            right: cursor.x.saturating_add(1),
            bottom: cursor.y.saturating_add(1),
        };
    }
    let monitor = unsafe { MonitorFromRect(&anchor, MONITOR_DEFAULTTONEAREST) };
    if monitor.is_null() {
        return None;
    }
    let mut info = MONITORINFO {
        cbSize: size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };
    if unsafe { GetMonitorInfoW(monitor, &mut info) } == 0 {
        return None;
    }
    let (mut dpi_x, mut dpi_y) = (96, 96);
    // Like winit's monitor-DPI query, this uses the icon monitor rather than an
    // unshown Slint window whose scale factor may still belong to another one.
    if unsafe { GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &mut dpi_x, &mut dpi_y) } < 0
        || dpi_x == 0
        || dpi_y == 0
    {
        let fallback = unsafe { GetDpiForWindow(hwnd) };
        dpi_x = if fallback == 0 { 96 } else { fallback };
        dpi_y = dpi_x;
    }
    let (width, height) = physical_size(logical_width, logical_height, dpi_x, dpi_y);
    placement(width, height, anchor, info.rcWork)
}

/// Owned modal dialogs and the native tray menu must not count as outside clicks.
pub fn foreground_is_own_process() -> bool {
    foreground_is_own_process_except(None)
}

/// Connections is a separate destination, even though it shares the process.
/// Its owned popups are excluded too; main-panel dialogs/menus remain internal.
pub fn foreground_is_own_process_except(excluded: Option<HWND>) -> bool {
    let foreground = unsafe { GetForegroundWindow() };
    if foreground.is_null() {
        return false;
    }
    let mut pid = 0;
    if unsafe { GetWindowThreadProcessId(foreground, &mut pid) } == 0 {
        return false;
    }
    internal_foreground(
        Some(foreground),
        pid,
        std::process::id(),
        excluded.filter(|window| !window.is_null()),
        |window| {
            // SAFETY: only HWNDs obtained from Windows are queried, never dereferenced.
            let owner = unsafe { GetWindow(window, GW_OWNER) };
            (!owner.is_null()).then_some(owner)
        },
    )
}

const MAX_OWNER_HOPS: usize = 64;

fn internal_foreground<W: Copy + Eq>(
    foreground: Option<W>,
    pid: u32,
    own_pid: u32,
    excluded: Option<W>,
    mut owner: impl FnMut(W) -> Option<W>,
) -> bool {
    let Some(mut window) = foreground else {
        return false;
    };
    if pid == 0 || pid != own_pid {
        return false;
    }
    let Some(excluded) = excluded else {
        return true;
    };
    for _ in 0..MAX_OWNER_HOPS {
        if window == excluded {
            return false;
        }
        match owner(window) {
            None => return true,
            Some(parent) if parent == window => return false,
            Some(parent) => window = parent,
        }
    }
    // A malformed/cyclic owner chain cannot keep an unfocused panel open forever.
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_main_popups_are_internal_but_connections_and_its_owned_dialogs_are_not() {
        let no_lookup = |_| -> Option<u32> { panic!("Owner lookup was unnecessary") };
        assert!(!internal_foreground(None, 7, 7, Some(10), no_lookup));
        assert!(!internal_foreground(Some(1), 0, 7, Some(10), no_lookup));
        assert!(!internal_foreground(Some(1), 8, 7, Some(10), no_lookup));
        assert!(internal_foreground(Some(1), 7, 7, None, no_lookup));
        assert!(!internal_foreground(Some(10), 7, 7, Some(10), no_lookup));
        // IDs are pure fixture values, not native HWNDs; no OS window is created.
        let owners = |window| match window {
            3 => Some(2),
            2 => Some(1),
            12 => Some(11),
            11 => Some(10),
            _ => None,
        };
        assert!(internal_foreground(Some(3), 7, 7, Some(10), owners));
        assert!(!internal_foreground(Some(12), 7, 7, Some(10), owners));
    }

    #[test]
    fn malformed_owner_cycles_are_bounded_and_do_not_keep_the_panel_open() {
        let mut queries = 0;
        let result = internal_foreground(Some(1), 7, 7, Some(10), |window| {
            queries += 1;
            Some(if window == 1 { 2 } else { 1 })
        });
        assert!(!result);
        assert_eq!(queries, MAX_OWNER_HOPS);
        let mut queries = 0;
        assert!(!internal_foreground(Some(1), 7, 7, Some(10), |window| {
            queries += 1;
            Some(window)
        }));
        assert_eq!(queries, 1);
    }

    fn rect(left: i32, top: i32, right: i32, bottom: i32) -> RECT {
        RECT {
            left,
            top,
            right,
            bottom,
        }
    }
    fn inside(popup: PopupGeometry, work: RECT) {
        assert!(popup.x >= work.left && popup.y >= work.top);
        assert!(i64::from(popup.x) + i64::from(popup.width) <= i64::from(work.right));
        assert!(i64::from(popup.y) + i64::from(popup.height) <= i64::from(work.bottom));
    }

    #[test]
    fn tray_popup_uses_each_taskbar_edge_without_leaving_the_work_area() {
        for (work, anchor, expected) in [
            (
                rect(0, 0, 1920, 1040),
                rect(1824, 1048, 1856, 1080),
                (1436, 312),
            ),
            (rect(0, 40, 1920, 1080), rect(1824, 4, 1856, 36), (1436, 48)),
            (rect(48, 0, 1920, 1080), rect(8, 1000, 40, 1032), (56, 312)),
            (
                rect(0, 0, 1872, 1080),
                rect(1880, 1000, 1912, 1032),
                (1444, 312),
            ),
        ] {
            let popup = placement(420, 720, anchor, work).unwrap();
            assert_eq!((popup.x, popup.y), expected);
            inside(popup, work);
        }
    }

    #[test]
    fn negative_monitor_coordinates_cursor_fallback_and_overflow_anchor_are_clamped() {
        for (work, anchor) in [
            (rect(-1920, 0, 0, 1040), rect(-48, 1048, -16, 1080)),
            (rect(1920, -1080, 3840, -40), rect(3780, -32, 3812, 0)),
            (rect(0, 0, 1280, 680), rect(1, 1, 2, 2)),
            (rect(0, 0, 1920, 1040), rect(1700, 900, 1732, 932)),
        ] {
            inside(placement(420, 720, anchor, work).unwrap(), work);
        }
    }

    #[test]
    fn monitor_dpi_is_applied_before_clamping_an_oversized_popup() {
        let work = rect(-1920, 0, 0, 1040);
        let anchor = rect(-48, 1048, -16, 1080);
        for (dpi, expected_width, expected_height) in
            [(96, 420, 720), (144, 630, 1040), (192, 840, 1040)]
        {
            let (width, height) = physical_size(420, 720, dpi, dpi);
            let popup = placement(width, height, anchor, work).unwrap();
            assert_eq!(
                (popup.width, popup.height),
                (expected_width, expected_height)
            );
            inside(popup, work);
        }
        let small = rect(-800, -600, -400, -100);
        let popup = placement(u32::MAX, u32::MAX, anchor, small).unwrap();
        assert_eq!(
            popup,
            PopupGeometry {
                x: -800,
                y: -600,
                width: 400,
                height: 500
            }
        );
        assert!(placement(0, 720, anchor, work).is_none());
        assert!(placement(420, 720, anchor, rect(0, 0, 0, 0)).is_none());
    }
}
