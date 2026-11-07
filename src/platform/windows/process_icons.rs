//! Read embedded icons from local executable resources for the Connections view.
use super::{process::image_path, wide};
use std::{ffi::OsStr, path::Path, ptr};
use windows_sys::Win32::{
    Graphics::Gdi::{
        BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC, CreateDIBSection, DIB_RGB_COLORS,
        DeleteDC, DeleteObject, GdiFlush, HBITMAP, HDC, SelectObject,
    },
    Storage::FileSystem::GetDriveTypeW,
    UI::{
        Shell::SHDefExtractIconW,
        WindowsAndMessaging::{DI_NORMAL, DestroyIcon, DrawIconEx, HICON},
    },
};

/// A square image of the requested pixel size (16–64) in straight-alpha RGBA.
pub fn process_icon(pid: u32, process_name: &str, size: u32) -> Option<Vec<u8>> {
    let path = image_path(pid).ok()?;
    let basename = Path::new(&path).file_name()?.to_str()?;
    if basename.to_lowercase() != process_name.to_lowercase() || !local_drive(&path) {
        return None;
    }
    rasterize(Path::new(&path).as_os_str(), size)
}

fn local_drive(path: &str) -> bool {
    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_FIXED: u32 = 3;
    const DRIVE_CDROM: u32 = 5;
    const DRIVE_RAMDISK: u32 = 6;
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    let [letter, b':', b'\\', ..] = path.as_bytes() else {
        return false;
    };
    if !letter.is_ascii_alphabetic() {
        return false;
    }
    let root = [u16::from(*letter), u16::from(b':'), u16::from(b'\\'), 0];
    // SAFETY: root is a NUL-terminated drive root and is borrowed only for this call.
    matches!(
        unsafe { GetDriveTypeW(root.as_ptr()) },
        DRIVE_REMOVABLE | DRIVE_FIXED | DRIVE_CDROM | DRIVE_RAMDISK
    )
}

struct Icon(HICON);
impl Drop for Icon {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: SHDefExtractIconW returns an owned icon handle.
            unsafe { DestroyIcon(self.0) };
        }
    }
}

fn rasterize(path: &OsStr, size: u32) -> Option<Vec<u8>> {
    if !(16..=64).contains(&size) {
        return None;
    }
    let mut icon = Icon(ptr::null_mut());
    let path = wide(path);
    // Request the actual physical size so Windows can choose the embedded frame
    // before scaling and DrawIconEx can paint at that same size.
    // SAFETY: path is NUL-terminated and the large-icon output is writable.
    let result =
        unsafe { SHDefExtractIconW(path.as_ptr(), 0, 0, &mut icon.0, ptr::null_mut(), size) };
    if result != 0 || icon.0.is_null() {
        return None;
    }
    let mut canvas = Canvas::new(size as i32)?;
    let black = canvas.draw(&icon, 0)?;
    let white = canvas.draw(&icon, 255)?;
    let mut rgba = Vec::with_capacity(black.len());
    let mut has_visible_pixels = false;
    for (black, white) in black
        .as_chunks::<4>()
        .0
        .iter()
        .zip(white.as_chunks::<4>().0)
    {
        // The difference between both backgrounds reveals transparency for
        // alpha-blended icons and traditional AND/XOR masks. Treat old
        // inversion pixels as opaque where a single RGBA color cannot invert.
        let alpha = 255 - white[1].saturating_sub(black[1]);
        if alpha == 0 {
            rgba.extend_from_slice(&[0, 0, 0, 0]);
        } else {
            has_visible_pixels = true;
            let alpha16 = u16::from(alpha);
            let straight =
                |channel| ((u16::from(channel) * 255 + alpha16 / 2) / alpha16).min(255) as u8;
            rgba.extend_from_slice(&[
                straight(black[2]),
                straight(black[1]),
                straight(black[0]),
                alpha,
            ]);
        }
    }
    has_visible_pixels.then_some(rgba)
}

struct Canvas {
    dc: HDC,
    bitmap: HBITMAP,
    bits: *mut u8,
    side: i32,
}

impl Canvas {
    fn new(side: i32) -> Option<Self> {
        // SAFETY: a null reference requests an owned memory DC.
        let dc = unsafe { CreateCompatibleDC(ptr::null_mut()) };
        if dc.is_null() {
            return None;
        }
        let info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: side,
                biHeight: -side,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut bits = ptr::null_mut();
        // SAFETY: info describes a top-down 32-bit bitmap; bits is a valid out
        // pointer. With no file mapping, the returned bitmap owns its pixels.
        let bitmap =
            unsafe { CreateDIBSection(dc, &info, DIB_RGB_COLORS, &mut bits, ptr::null_mut(), 0) };
        let canvas = Self {
            dc,
            bitmap,
            bits: bits.cast(),
            side,
        };
        if canvas.bitmap.is_null() || canvas.bits.is_null() {
            return None;
        }
        // SAFETY: the bitmap and memory DC are live and private to this canvas.
        let previous = unsafe { SelectObject(canvas.dc, canvas.bitmap) };
        (!previous.is_null()).then_some(canvas)
    }

    fn draw(&mut self, icon: &Icon, background: u8) -> Option<Vec<u8>> {
        let bytes = (self.side * self.side * 4) as usize;
        let mut pixels = vec![0; bytes];
        // SAFETY: the DIB has `side * side * 4` bytes of writable storage
        // and is private to this thread. Flush GDI before reading its pixels.
        unsafe {
            self.bits.write_bytes(background, bytes);
            let drawn = DrawIconEx(
                self.dc,
                0,
                0,
                icon.0,
                self.side,
                self.side,
                0,
                ptr::null_mut(),
                DI_NORMAL,
            );
            let flushed = GdiFlush();
            if drawn == 0 || flushed == 0 {
                return None;
            }
            ptr::copy_nonoverlapping(self.bits, pixels.as_mut_ptr(), bytes);
        }
        Some(pixels)
    }
}

impl Drop for Canvas {
    fn drop(&mut self) {
        // SAFETY: deleting this private DC releases the selection before we
        // delete its owned DIB. The default bitmap belongs to GDI.
        unsafe {
            DeleteDC(self.dc);
            if !self.bitmap.is_null() {
                DeleteObject(self.bitmap);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_icon_rasterizes_at_requested_sizes_with_transparency() {
        let path = Path::new(env!("OUT_DIR")).join("true-proxy.ico");
        for size in [16, 20, 25, 30, 40, 64] {
            let pixels = rasterize(path.as_os_str(), size).unwrap();
            assert_eq!(pixels.len(), (size * size * 4) as usize);
            let (pixels, _) = pixels.as_chunks::<4>();
            assert!(pixels.iter().any(|pixel| pixel[3] == 0));
            assert!(pixels.iter().any(|pixel| pixel[3] == 255));
        }
        assert!(rasterize(path.as_os_str(), 15).is_none());
        assert!(rasterize(path.as_os_str(), 65).is_none());
    }
}
