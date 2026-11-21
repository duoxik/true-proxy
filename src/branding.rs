//! Render the SVG used by the window at the sizes needed by the EXE and tray.
use resvg::{tiny_skia, usvg};
use std::borrow::Cow;

const SVG: &str = include_str!("../assets/icon.svg");

pub fn rgba(size: u32, active: Option<bool>) -> Vec<u8> {
    let svg = match active {
        None => Cow::Borrowed(SVG),
        Some(active) => {
            let color = if active { "#C8F72C" } else { "#F56070" };
            Cow::Owned(SVG.replace(
                "</svg>",
                &format!(
                    r##"<circle cx="53" cy="53" r="10.5" fill="#101218"/>
  <circle cx="53" cy="53" r="7.5" fill="{color}"/>
</svg>"##
                ),
            ))
        }
    };
    let tree = usvg::Tree::from_str(&svg, &usvg::Options::default())
        .expect("The application icon must be a valid SVG");
    let mut pixmap = tiny_skia::Pixmap::new(size, size).expect("Invalid application icon size");
    let transform = tiny_skia::Transform::from_scale(
        size as f32 / tree.size().width(),
        size as f32 / tree.size().height(),
    );
    resvg::render(&tree, transform, &mut pixmap.as_mut());
    pixmap.take_demultiplied()
}
