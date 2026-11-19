use crate::{MainWindow, NoticeBackdrop};
use image::{Rgba, RgbaImage, imageops};
use slint::{
    ComponentHandle, Image, PhysicalPosition, PhysicalSize, Rgba8Pixel, SharedPixelBuffer,
};

pub(super) fn wire(ui: &MainWindow) {
    let weak = ui.as_weak();
    ui.global::<NoticeBackdrop>()
        .on_sample(move |x, y, width, height, radius| {
            let Some(ui) = weak.upgrade() else {
                return Image::default();
            };
            let window = ui.window();
            let scale = window.scale_factor();
            let size = window.size();
            let physical_width = (width * scale).round() as u32;
            let physical_height = (height * scale).round() as u32;
            let material = ui.global::<NoticeBackdrop>();
            let blur = material.get_blur().clamp(0, 24);
            // A software snapshot temporarily needs two full-size RGBA buffers.
            if !window.is_visible()
                || material.get_capturing()
                || blur == 0
                || material.get_transparency() <= 0
                || physical_width == 0
                || physical_height == 0
                || u64::from(size.width) * u64::from(size.height) > 10_000_000
                || u64::from(physical_width) * u64::from(physical_height) > 4_000_000
            {
                return Image::default();
            }
            material.set_capturing(true);
            let snapshot = window.take_snapshot();
            material.set_capturing(false);
            let Ok(snapshot) = snapshot else {
                return Image::default();
            };
            let pixels = blur_region(
                &snapshot,
                PhysicalPosition::new((x * scale).round() as i32, (y * scale).round() as i32),
                PhysicalSize::new(physical_width, physical_height),
                radius * scale,
                blur as f32 * scale,
                scale,
            );
            Image::from_rgba8(pixels)
        });
}

fn blur_region(
    source: &SharedPixelBuffer<Rgba8Pixel>,
    origin: PhysicalPosition,
    size: PhysicalSize,
    radius: f32,
    blur_px: f32,
    scale: f32,
) -> SharedPixelBuffer<Rgba8Pixel> {
    let PhysicalSize { width, height } = size;
    // A light blur retains fine detail. Wider kernels can sample a coarser grid.
    let step = (blur_px / 2.).min(4. * scale).round().max(1.) as u32;
    let sigma = blur_px / step as f32;
    let halo = (3. * sigma).ceil() as u32;
    let cols = width.div_ceil(step);
    let rows = height.div_ceil(step);
    let source_width = source.width() as usize;
    let sample = |sx: i64, sy: i64| {
        let col = sx.clamp(0, i64::from(source.width()) - 1) as usize;
        let row = sy.clamp(0, i64::from(source.height()) - 1) as usize;
        source.as_slice()[row * source_width + col]
    };
    let reduced = RgbaImage::from_fn(cols + halo * 2, rows + halo * 2, |col, row| {
        let sx = i64::from(origin.x) + (i64::from(col) - i64::from(halo)) * i64::from(step);
        let sy = i64::from(origin.y) + (i64::from(row) - i64::from(halo)) * i64::from(step);
        let a = i64::from(step / 4);
        let b = i64::from(3 * step / 4);
        let taps = [
            sample(sx + a, sy + a),
            sample(sx + b, sy + a),
            sample(sx + a, sy + b),
            sample(sx + b, sy + b),
        ];
        let mean = |channel: fn(Rgba8Pixel) -> u8| {
            ((taps.iter().map(|p| u16::from(channel(*p))).sum::<u16>() + 2) / 4) as u8
        };
        Rgba([mean(|p| p.r), mean(|p| p.g), mean(|p| p.b), 255])
    });
    let blurred = imageops::fast_blur(&reduced, sigma);
    let interior = imageops::crop_imm(&blurred, halo, halo, cols, rows);
    // Slint's software image sampler uses nearest neighbours when stretched.
    // Reconstruct at device resolution for smooth tones and anti-aliased corners.
    let mut glass = imageops::resize(&*interior, width, height, imageops::FilterType::Triangle);
    let radius = radius.clamp(0., width.min(height) as f32 / 2.);
    for dy in 0..radius.ceil() as u32 {
        for dx in 0..radius.ceil() as u32 {
            let distance = (radius - dx as f32 - 0.5).hypot(radius - dy as f32 - 0.5);
            let alpha = ((radius + 0.5 - distance).clamp(0., 1.) * 255.).round() as u8;
            for (col, row) in [
                (dx, dy),
                (width - 1 - dx, dy),
                (dx, height - 1 - dy),
                (width - 1 - dx, height - 1 - dy),
            ] {
                glass.get_pixel_mut(col, row)[3] = alpha;
            }
        }
    }
    SharedPixelBuffer::clone_from_slice(glass.as_raw(), width, height)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blur_uses_the_halo_and_preserves_rounded_corners_at_high_dpi() {
        let mut source = SharedPixelBuffer::<Rgba8Pixel>::new(160, 120);
        for row in source.make_mut_slice().as_chunks_mut::<160>().0 {
            row[..40].fill(Rgba8Pixel::new(255, 255, 255, 255));
        }
        let origin = PhysicalPosition::new(40, -2);
        let size = PhysicalSize::new(100, 100);
        let glass = blur_region(&source, origin, size, 16., 18., 2.);
        let row = &glass.as_slice()[50 * 100..51 * 100];
        assert!(row[0].r > row[12].r && row[12].r > row[40].r);
        assert_eq!(row[0].a, 255);
        assert_eq!(glass.as_slice()[0].a, 0);
        assert_eq!(glass.as_slice()[99].a, 0);
        let lighter = blur_region(&source, origin, size, 16., 2., 2.);
        let stronger = blur_region(&source, origin, size, 16., 48., 2.);
        let sample = 50 * 100 + 12;
        assert!(lighter.as_slice()[sample].r < glass.as_slice()[sample].r);
        assert!(glass.as_slice()[sample].r < stronger.as_slice()[sample].r);
    }
}
