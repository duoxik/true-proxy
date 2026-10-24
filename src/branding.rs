//! One small, dependency-free logo renderer for the executable, window and tray.
//! Coordinates are in a 64 px design space; coverage is supersampled for small icons.
pub fn rgba(size: u32, active: Option<bool>) -> Vec<u8> {
    let mut pixels = vec![0; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let mut sum = [0u32; 4];
            for dy in 0..4 {
                for dx in 0..4 {
                    let color = sample(
                        (x as f32 + (dx as f32 + 0.5) / 4.) * 64. / size as f32,
                        (y as f32 + (dy as f32 + 0.5) / 4.) * 64. / size as f32,
                        active,
                    );
                    for i in 0..4 {
                        sum[i] += color[i] as u32;
                    }
                }
            }
            let offset = ((y * size + x) * 4) as usize;
            for i in 0..4 {
                pixels[offset + i] = (sum[i] / 16) as u8;
            }
            // Keep RGB unpremultiplied at the translucent edge.
            for i in 0..3 {
                pixels[offset + i] = (sum[i] * 255).checked_div(sum[3]).unwrap_or(0) as u8;
            }
        }
    }
    pixels
}

fn sample(x: f32, y: f32, active: Option<bool>) -> [u8; 4] {
    let mut color = [0, 0, 0, 0];
    let cx = x.clamp(19., 45.);
    let cy = y.clamp(19., 45.);
    if (x - cx).hypot(y - cy) <= 16. {
        color = [42, 53, 94, 255];
        if (x - cx).hypot(y - cy) >= 14.8 {
            color = [129, 147, 243, 255];
        }
        let paths = [
            ((16., 24.), (46., 24.)),
            ((38., 16.), (46., 24.)),
            ((38., 32.), (46., 24.)),
            ((48., 40.), (18., 40.)),
            ((26., 32.), (18., 40.)),
            ((26., 48.), (18., 40.)),
        ];
        if paths.into_iter().any(|(a, b)| distance(x, y, a, b) <= 2.1) {
            color = [237, 240, 255, 255];
        }
    }
    if let Some(active) = active {
        let radius = (x - 53.).hypot(y - 53.);
        if radius <= 10.5 {
            color = [16, 18, 24, 255];
        }
        if radius <= 7.5 {
            color = if active {
                [66, 220, 144, 255]
            } else {
                [245, 96, 112, 255]
            };
        }
    }
    color
}

fn distance(x: f32, y: f32, a: (f32, f32), b: (f32, f32)) -> f32 {
    let (dx, dy) = (b.0 - a.0, b.1 - a.1);
    let along = (((x - a.0) * dx + (y - a.1) * dy) / (dx * dx + dy * dy)).clamp(0., 1.);
    (x - a.0 - along * dx).hypot(y - a.1 - along * dy)
}
