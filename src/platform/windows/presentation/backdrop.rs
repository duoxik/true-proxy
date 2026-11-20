use std::{mem::size_of_val, ptr};
use windows_sys::Win32::{
    Foundation::{HWND, POINT, RECT},
    Graphics::{Dwm::*, Gdi::ScreenToClient},
    UI::{
        Accessibility::{HCF_HIGHCONTRASTON, HIGHCONTRASTW},
        Controls::{MARGINS, WM_MOUSELEAVE},
        HiDpi::{GetDpiForWindow, GetSystemMetricsForDpi},
        Input::KeyboardAndMouse::{TME_LEAVE, TME_NONCLIENT, TRACKMOUSEEVENT, TrackMouseEvent},
        Shell::{DefSubclassProc, RemoveWindowSubclass, SHRegGetBoolUSValueW, SetWindowSubclass},
        WindowsAndMessaging::*,
    },
};

const FRAME_ID: usize = 1;
const FRAME_PROPERTY: *const u16 = windows_sys::core::w!("TrueProxy.BackdropFrame");
// Keep this in step with the titlebar row in ui/app.slint.
const TITLE_HEIGHT_DIP: i32 = 32;
const BUTTON_WIDTH_DIP: i32 = 46;

pub fn sidebar_backdrop_allowed() -> bool {
    let mut contrast = HIGHCONTRASTW::default();
    contrast.cbSize = size_of_val(&contrast) as u32;
    unsafe {
        let high_contrast = SystemParametersInfoW(
            SPI_GETHIGHCONTRAST,
            contrast.cbSize,
            (&raw mut contrast).cast(),
            0,
        ) != 0
            && contrast.dwFlags & HCF_HIGHCONTRASTON != 0;
        !high_contrast
            && SHRegGetBoolUSValueW(
                windows_sys::core::w!(
                    r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
                ),
                windows_sys::core::w!("EnableTransparency"),
                0,
                1,
            ) != 0
    }
}

/// Route Slint's custom titlebar buttons to the normal Windows system commands,
/// including WM_CLOSE which winit delivers to the application's close-to-tray handler.
#[allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "User32 validates the opaque HWND; neither call dereferences caller memory"
)]
pub fn caption_action(hwnd: HWND, index: i32) {
    let command = match index {
        0 => SC_MINIMIZE,
        1 if unsafe { IsZoomed(hwnd) } != 0 => SC_RESTORE,
        1 => SC_MAXIMIZE,
        2 => SC_CLOSE,
        _ => return,
    };
    unsafe { PostMessageW(hwnd, WM_SYSCOMMAND, command as usize, 0) };
}

/// Apply a DWM material to an owned winit window on its UI thread. Keep the
/// standard overlapped-window style so Windows still owns system commands,
/// resizing, snapping, and the system menu.
pub fn apply_sidebar_backdrop(hwnd: HWND, mode: i32, dark: bool) -> bool {
    let mode = if mode != 0 && sidebar_backdrop_allowed() {
        mode
    } else {
        0
    };
    apply_material(hwnd, mode, dark)
}

fn apply_material(hwnd: HWND, mode: i32, dark: bool) -> bool {
    let installed = unsafe { !GetPropW(hwnd, FRAME_PROPERTY).is_null() };
    let material = match mode {
        1 => DWMSBT_MAINWINDOW,
        2 => DWMSBT_TRANSIENTWINDOW,
        _ => {
            if installed {
                restore_frame(hwnd);
            }
            return false;
        }
    };

    // Slint's winit backend already creates a transparent window. Its software
    // buffer carries premultiplied BGRA through BitBlt to the DWM redirection surface.
    let mut composed = 0;
    let enabled = unsafe { DwmIsCompositionEnabled(&mut composed) >= 0 && composed != 0 }
        && attribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, i32::from(dark))
        && attribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, material)
        && attribute(hwnd, DWMWA_CAPTION_COLOR, DWMWA_COLOR_DEFAULT as i32)
        && extend_frame(hwnd, -1)
        && (installed
            || unsafe {
                SetWindowSubclass(hwnd, Some(frame_proc), FRAME_ID, 0) != 0
                    && SetPropW(hwnd, FRAME_PROPERTY, hwnd) != 0
            });
    if !enabled {
        restore_frame(hwnd);
        return false;
    }
    if !installed {
        refresh_frame(hwnd);
    }
    true
}

fn attribute(hwnd: HWND, attr: i32, value: i32) -> bool {
    unsafe {
        DwmSetWindowAttribute(
            hwnd,
            attr as u32,
            (&raw const value).cast(),
            size_of_val(&value) as u32,
        ) >= 0
    }
}

fn extend_frame(hwnd: HWND, margin: i32) -> bool {
    let margins = MARGINS {
        cxLeftWidth: margin,
        cxRightWidth: margin,
        cyTopHeight: margin,
        cyBottomHeight: margin,
    };
    unsafe { DwmExtendFrameIntoClientArea(hwnd, &margins) >= 0 }
}

fn restore_frame(hwnd: HWND) {
    unsafe { RemovePropW(hwnd, FRAME_PROPERTY) };
    let removed = unsafe { RemoveWindowSubclass(hwnd, Some(frame_proc), FRAME_ID) };
    attribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, DWMSBT_NONE);
    extend_frame(hwnd, 0);
    if removed != 0 {
        refresh_frame(hwnd);
    }
}

fn refresh_frame(hwnd: HWND) {
    unsafe {
        SetWindowPos(
            hwnd,
            ptr::null_mut(),
            0,
            0,
            0,
            0,
            SWP_FRAMECHANGED | SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER,
        );
    }
}

unsafe extern "system" fn frame_proc(
    hwnd: HWND,
    msg: u32,
    wp: usize,
    lp: isize,
    _id: usize,
    _data: usize,
) -> isize {
    unsafe {
        match msg {
            // Both forms begin with the proposed RECT. DefWindowProc retains
            // the native side/bottom insets; reclaim only the caption itself.
            WM_NCCALCSIZE if lp != 0 => {
                let rect = lp as *mut RECT;
                let proposed = *rect;
                DefSubclassProc(hwnd, msg, wp, lp);
                let top_inset = if IsZoomed(hwnd) != 0 {
                    ((*rect).left - proposed.left).max(0)
                } else {
                    1
                };
                // A minimized HWND can have an empty rectangle. A negative
                // client height would be reported by WM_SIZE as 65535 pixels.
                (*rect).top = (proposed.top + top_inset).min((*rect).bottom);
                return 0;
            }
            WM_NCHITTEST => {
                let native = DefSubclassProc(hwnd, msg, wp, lp);
                if !matches!(
                    native as u32,
                    HTCLIENT | HTCAPTION | HTMINBUTTON | HTMAXBUTTON | HTCLOSE | HTSYSMENU
                ) {
                    return native;
                }
                return title_hit(hwnd, client_point(hwnd, lp)) as isize;
            }
            WM_NCMOUSEMOVE => {
                // Send hover to Slint and keep the real non-client event for
                // Windows 11's snap-layout flyout on HTMAXBUTTON.
                let point = client_point(hwnd, lp);
                DefSubclassProc(hwnd, WM_MOUSEMOVE, 0, pack(point));
                let mut track = TRACKMOUSEEVENT {
                    cbSize: std::mem::size_of::<TRACKMOUSEEVENT>() as u32,
                    dwFlags: TME_NONCLIENT | TME_LEAVE,
                    hwndTrack: hwnd,
                    dwHoverTime: 0,
                };
                TrackMouseEvent(&mut track);
            }
            WM_MOUSELEAVE | WM_NCMOUSELEAVE => {
                // winit tracks client leave, while our buttons are non-client
                // hit targets. Crossing that boundary is still inside Slint.
                let mut cursor = POINT::default();
                let mut client = RECT::default();
                if GetCursorPos(&mut cursor) != 0 && WindowFromPoint(cursor) == hwnd {
                    ScreenToClient(hwnd, &mut cursor);
                    GetClientRect(hwnd, &mut client);
                    if cursor.x >= 0
                        && cursor.x < client.right
                        && cursor.y >= 0
                        && cursor.y < client.bottom
                    {
                        return 0;
                    }
                }
                return DefSubclassProc(hwnd, WM_MOUSELEAVE, 0, 0);
            }
            WM_NCLBUTTONDOWN | WM_NCLBUTTONUP | WM_NCLBUTTONDBLCLK
                if matches!(wp as u32, HTMINBUTTON | HTMAXBUTTON | HTCLOSE) =>
            {
                // winit handles ordinary capture/release and forwards to the
                // matching accessible Slint button. A canceled click stays canceled.
                let point = pack(client_point(hwnd, lp));
                DefSubclassProc(hwnd, WM_MOUSEMOVE, 0, point);
                return if msg == WM_NCLBUTTONUP {
                    DefSubclassProc(hwnd, WM_LBUTTONUP, 0, point)
                } else {
                    DefSubclassProc(hwnd, WM_LBUTTONDOWN, 1, point)
                };
            }
            WM_NCDESTROY => {
                RemovePropW(hwnd, FRAME_PROPERTY);
                RemoveWindowSubclass(hwnd, Some(frame_proc), FRAME_ID);
            }
            _ => {}
        }
        DefSubclassProc(hwnd, msg, wp, lp)
    }
}

unsafe fn client_point(hwnd: HWND, packed: isize) -> POINT {
    let mut point = POINT {
        x: packed as i16 as i32,
        y: (packed >> 16) as i16 as i32,
    };
    unsafe { ScreenToClient(hwnd, &mut point) };
    point
}

fn pack(point: POINT) -> isize {
    ((point.y as u16 as isize) << 16) | point.x as u16 as isize
}

unsafe fn title_hit(hwnd: HWND, p: POINT) -> u32 {
    unsafe {
        let dpi = GetDpiForWindow(hwnd).max(96);
        let dip = |value: i32| (value * dpi as i32 + 48) / 96;
        let title = dip(TITLE_HEIGHT_DIP);
        if p.y >= title {
            return HTCLIENT;
        }
        let mut client = RECT::default();
        GetClientRect(hwnd, &mut client);
        let from_right = client.right - p.x;
        let border = GetSystemMetricsForDpi(SM_CYSIZEFRAME, dpi)
            + GetSystemMetricsForDpi(SM_CXPADDEDBORDER, dpi);
        if IsZoomed(hwnd) == 0 && p.y < border {
            return if p.x < border {
                HTTOPLEFT
            } else if from_right <= border {
                HTTOPRIGHT
            } else {
                HTTOP
            };
        }
        if from_right <= dip(BUTTON_WIDTH_DIP) {
            HTCLOSE
        } else if from_right <= dip(BUTTON_WIDTH_DIP * 2) {
            HTMAXBUTTON
        } else if from_right <= dip(BUTTON_WIDTH_DIP * 3) {
            HTMINBUTTON
        } else if p.x < title {
            HTSYSMENU
        } else {
            HTCAPTION
        }
    }
}
