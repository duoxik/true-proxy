//! Development fixtures rendered entirely into memory. This example never
//! creates a native window/tray, starts WinDivert, reads a user profile, touches
//! the clipboard, or performs a network request.
//!
//! Run after the normal development environment is prepared:
//! cargo run --locked --example ui_snapshot -- .tools/ui-headless
use anyhow::{Context, Result, ensure};
use slint::{
    ComponentHandle, ModelRc, PhysicalSize, VecModel, Window, WindowSize,
    platform::{
        Platform, PlatformError, Renderer, WindowAdapter, WindowEvent,
        software_renderer::{PremultipliedRgbaColor, RepaintBufferType, SoftwareRenderer},
    },
};
use std::{
    cell::{Cell, RefCell},
    fs::{self, File},
    io::BufWriter,
    path::{Path, PathBuf},
    rc::{Rc, Weak},
    time::{Duration, Instant},
};

slint::include_modules!();
#[path = "../src/app/json_highlight.rs"]
mod json_highlight;

struct MemoryWindow {
    window: Window,
    renderer: SoftwareRenderer,
    size: Cell<PhysicalSize>,
    visible: Cell<bool>,
}
impl MemoryWindow {
    fn new() -> Rc<Self> {
        Rc::new_cyclic(|weak: &Weak<Self>| Self {
            window: Window::new(weak.clone()),
            renderer: SoftwareRenderer::new_with_repaint_buffer_type(RepaintBufferType::NewBuffer),
            size: Cell::new(PhysicalSize::new(1240, 780)),
            visible: Cell::new(false),
        })
    }
}
impl WindowAdapter for MemoryWindow {
    fn window(&self) -> &Window {
        &self.window
    }
    fn renderer(&self) -> &dyn Renderer {
        &self.renderer
    }
    fn size(&self) -> PhysicalSize {
        self.size.get()
    }
    fn set_visible(&self, visible: bool) -> Result<(), PlatformError> {
        self.visible.set(visible);
        Ok(())
    }
    fn set_size(&self, size: WindowSize) {
        let scale = self.window.scale_factor();
        self.size.set(size.to_physical(scale));
        self.window.dispatch_event(WindowEvent::Resized {
            size: size.to_logical(scale),
        });
    }
}

struct MemoryPlatform {
    windows: Rc<RefCell<Vec<Rc<MemoryWindow>>>>,
    started: Instant,
}
impl Platform for MemoryPlatform {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        let adapter = MemoryWindow::new();
        self.windows.borrow_mut().push(adapter.clone());
        Ok(adapter)
    }
    fn duration_since_start(&self) -> Duration {
        self.started.elapsed()
    }
}

fn model<T: Clone + 'static>(rows: Vec<T>) -> ModelRc<T> {
    Rc::new(VecModel::from(rows)).into()
}

fn save(adapter: &MemoryWindow, destination: &Path) -> Result<()> {
    ensure!(adapter.visible.get(), "Memory window was not made visible");
    slint::platform::update_timers_and_animations();
    let size = adapter.size.get();
    let mut pixels =
        vec![PremultipliedRgbaColor::default(); size.width as usize * size.height as usize];
    let _ = adapter.renderer.render(&mut pixels, size.width as usize);
    let mut rgba = Vec::with_capacity(pixels.len() * 4);
    for pixel in pixels {
        let unpremultiply = |value: u8| {
            if pixel.alpha == 0 {
                0
            } else {
                (u16::from(value) * 255 / u16::from(pixel.alpha)).min(255) as u8
            }
        };
        rgba.extend_from_slice(&[
            unpremultiply(pixel.red),
            unpremultiply(pixel.green),
            unpremultiply(pixel.blue),
            pixel.alpha,
        ]);
    }
    let mut encoder = png::Encoder::new(
        BufWriter::new(File::create(destination)?),
        size.width,
        size.height,
    );
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header()?;
    writer.write_image_data(&rgba)?;
    writer.finish()?;
    Ok(())
}

fn filter(key: &str, label: &str, checked: bool) -> ConnectionFilterOption {
    ConnectionFilterOption {
        key: key.into(),
        label: label.into(),
        checked,
    }
}

fn main() -> Result<()> {
    let destination = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".tools/ui-headless"));
    fs::create_dir_all(&destination)?;
    let windows = Rc::new(RefCell::new(Vec::new()));
    slint::platform::set_platform(Box::new(MemoryPlatform {
        windows: windows.clone(),
        started: Instant::now(),
    }))
    .map_err(|error| anyhow::anyhow!("Memory platform: {error}"))?;

    let ui = MainWindow::new()?;
    let main_adapter = windows
        .borrow()
        .last()
        .cloned()
        .context("No memory window")?;
    ui.set_active(true);
    ui.set_status("Routing is active".into());
    ui.set_app_version(env!("CARGO_PKG_VERSION").into());
    ui.set_uptime("00:14:37".into());
    ui.set_uploaded("2.1 MB".into());
    ui.set_downloaded("16.4 MB".into());
    ui.set_upload_rate("24.0 KB/s".into());
    ui.set_download_rate("38.0 KB/s".into());
    ui.set_upload_share(2.1 / (2.1 + 16.4));
    ui.set_has_transfer(true);
    ui.set_connection_count("4".into());
    ui.set_proxy_names(model(vec!["VPN".into(), "Work".into()]));
    ui.set_proxies(model(vec![
        ProxyRow {
            id: "p".into(),
            key: "proxy:p".into(),
            name: "VPN".into(),
            address: "192.0.2.10:1080".into(),
            status: "3 ms".into(),
            location: "Frankfurt am Main, DE".into(),
            flag_index: include_str!("../assets/country-flags.txt")
                .split_ascii_whitespace()
                .position(|code| code == "DE")
                .unwrap() as i32
                + 1,
            health: 2,
            udp: true,
        },
        ProxyRow {
            id: "q".into(),
            key: "proxy:q".into(),
            name: "Work".into(),
            address: "127.0.0.1:1080".into(),
            status: "".into(),
            location: "".into(),
            flag_index: 0,
            health: 3,
            udp: false,
        },
    ]));
    ui.set_rules(model(vec![
        RuleRow {
            id: "apps".into(),
            name: "Applications".into(),
            route: "Proxy · VPN".into(),
            enabled: true,
            priority: 2,
        },
        RuleRow {
            id: "game".into(),
            name: "Game".into(),
            route: "Proxy · VPN".into(),
            enabled: false,
            priority: 3,
        },
    ]));
    ui.set_enabled_rule_count(1);
    ui.window().set_size(PhysicalSize::new(1240, 780));
    ui.show()?; // Only MemoryWindow::set_visible; no OS window exists.
    for (page, name) in [(0, "home"), (1, "routes"), (2, "proxies"), (4, "settings")] {
        ui.set_page(page);
        save(&main_adapter, &destination.join(format!("{name}.png")))?;
    }
    ui.set_page(1);
    ui.set_dialog(2);
    ui.set_form_name("Game via VPN".into());
    ui.set_form_processes(model(vec![
        "destiny2.exe".into(),
        "destiny2launcher.exe".into(),
    ]));
    ui.set_form_action(0);
    save(&main_adapter, &destination.join("rule-form.png"))?;
    ui.set_dialog(1);
    ui.set_page(2);
    ui.set_form_name("VPN".into());
    ui.set_form_host("192.0.2.10".into());
    ui.set_form_port("1080".into());
    save(&main_adapter, &destination.join("proxy-form.png"))?;
    let import_json = r#"{
  "version": 2,
  "proxies": [
    {
      "id": "vpn",
      "name": "VPN",
      "host": "127.0.0.1",
      "port": 1080
    }
  ],
  "rules": [],
  "default_action": {
    "kind": "direct"
  }
}"#;
    let _ = true_proxy::profile::Profile::parse(import_json)?;
    ui.set_dialog(3);
    ui.set_page(4);
    ui.set_import_json(import_json.into());
    ui.set_import_lines(model(
        import_json
            .lines()
            .enumerate()
            .map(|(index, text)| JsonLine {
                number: index as i32,
                text: json_highlight::line(text),
            })
            .collect(),
    ));
    ui.set_import_valid(true);
    ui.set_import_summary("Proxies: 1 · Rules: 0 · Default route: Direct".into());
    save(&main_adapter, &destination.join("json-import.png"))?;
    ui.set_dialog(0);
    ui.set_page(3);
    let connections = ui.global::<ConnectionMonitor>();
    connections.set_connection_route_filters(model(vec![
        filter("all", "All", false),
        filter("proxy", "Proxy", true),
        filter("direct", "Direct", false),
        filter("block", "Blocked", false),
    ]));
    connections.set_connection_status_filters(model(vec![
        filter("all", "All", false),
        filter("0", "Connecting", true),
        filter("1", "Active", true),
        filter("2", "Closing", true),
        filter("3", "Closed", false),
        filter("4", "Failed", false),
        filter("5", "Blocked", false),
        filter("6", "Stopped", false),
    ]));
    connections.set_connection_event_count(3);
    connections.set_filtered_event_count(3);
    connections.set_active_connection_count(3);
    connections.set_total_sent("2.0 MB".into());
    connections.set_total_received("16.4 MB".into());
    connections.set_total_traffic("18.4 MB".into());
    let rows = model(vec![
        LogRow {
            id: "1".into(),
            process: "browser.exe".into(),
            pid: "PID 100".into(),
            destination: "TCP · 203.0.113.7:443".into(),
            route: "Proxy · VPN".into(),
            message: "TCP · Applications · example.com".into(),
            source: "192.0.2.30:51001".into(),
            started: "21:11:48".into(),
            elapsed: "8.6s".into(),
            status: "Active".into(),
            state: 1,
        },
        LogRow {
            id: "2".into(),
            process: "browser.exe".into(),
            pid: "PID 100".into(),
            destination: "TCP · 198.51.100.9:443".into(),
            route: "Proxy · VPN".into(),
            message: "TCP · Applications · DNS name unknown".into(),
            source: "192.0.2.30:51002".into(),
            started: "21:11:49".into(),
            elapsed: "7.1s".into(),
            status: "Connecting".into(),
            state: 0,
        },
    ]);
    connections.set_process_summaries(model(vec![
        ProcessSummary {
            name: "browser.exe".into(),
            icon: slint::Image::default(),
            active: 2,
            events: 2,
            uploaded: "1.2 MB".into(),
            downloaded: "8.6 MB".into(),
            expanded: true,
            connections: rows,
        },
        ProcessSummary {
            name: "game.exe".into(),
            icon: slint::Image::default(),
            active: 1,
            events: 1,
            uploaded: "856 KB".into(),
            downloaded: "7.8 MB".into(),
            expanded: false,
            connections: model(vec![]),
        },
    ]));
    save(&main_adapter, &destination.join("connections.png"))?;
    ui.set_page(5);
    let logs = ui.global::<TechnicalLogs>();
    logs.set_total(3);
    logs.set_visible_count(3);
    logs.set_recording(true);
    logs.set_text(
        "12:18:41  INF  [Backend] UI preview started\n\
         12:18:44  INF  [Connections] browser.exe · 203.0.113.7:443 · VPN · TCP · Applications\n\
         12:18:47  ERR  [Connections] game.exe · 198.51.100.28:443 · VPN · Sample SOCKS5 timeout"
            .into(),
    );
    save(&main_adapter, &destination.join("logs.png"))?;
    ui.hide()?;
    println!("Headless fixture PNGs: {}", destination.display());
    Ok(())
}
