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
    ui.set_dark_theme(false);
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
    ui.set_traffic_scale(model(vec![
        "60 KB/s".into(),
        "40 KB/s".into(),
        "20 KB/s".into(),
        "0 B/s".into(),
    ]));
    ui.set_upload_share(2.1 / (2.1 + 16.4));
    ui.set_has_transfer(true);
    ui.set_connection_count("4".into());
    // Deterministic chart fixture, confined to this offline example.
    let chart = |amplitude: f64| {
        use std::fmt::Write;
        let mut path = String::new();
        for i in 0..60 {
            let y = 98.0
                - amplitude * (0.5 + 0.25 * (i as f64 * 0.6).sin() + 0.2 * (i as f64 * 0.17).sin());
            let _ = write!(
                path,
                "{}{} {y:.2} ",
                if i == 0 { 'M' } else { 'L' },
                i as f64 * 600.0 / 59.0
            );
        }
        path
    };
    ui.set_download_path(chart(80.0).into());
    ui.set_upload_path(chart(9.0).into());
    ui.set_proxy_names(model(vec!["VPN".into(), "Work".into()]));
    ui.set_proxies(model(vec![
        ProxyRow {
            id: "p".into(),
            key: "proxy:p".into(),
            name: "VPN".into(),
            address: "192.0.2.10:1080".into(),
            status: "0 ms".into(),
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
                text: json_highlight::line(text, false),
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
    #[cfg(windows)]
    xray_previews(&ui, &main_adapter, &destination)?;
    ui.set_dark_theme(true);
    ui.set_page(1);
    save(&main_adapter, &destination.join("routes-dark.png"))?;
    ui.set_page(0);
    save(&main_adapter, &destination.join("dashboard-dark.png"))?;
    ui.window().set_size(slint::LogicalSize::new(960., 640.));
    save(
        &main_adapter,
        &destination.join("dashboard-dark-compact.png"),
    )?;
    ui.window().set_size(slint::LogicalSize::new(1240., 780.));
    ui.set_page(3);
    save(&main_adapter, &destination.join("connections-dark.png"))?;
    ui.set_page(4);
    ui.set_settings_section(0);
    save(&main_adapter, &destination.join("settings-dark.png"))?;
    #[cfg(windows)]
    {
        let xray = ui.global::<XrayModule>();
        xray.set_status("".into());
        xray.set_section(0);
        ui.set_page(6);
        save(&main_adapter, &destination.join("xray-dashboard-dark.png"))?;
    }
    // Recheck the full page family in both themes and at the minimum window size.
    // These are development fixtures only, never user profile or network state.
    for dark in [true, false] {
        ui.set_dark_theme(dark);
        let theme = if dark { "dark" } else { "light" };
        for (width, height, size) in [(1240, 780, "normal"), (960, 640, "compact")] {
            ui.window().set_size(PhysicalSize::new(width, height));
            for (page, name) in [
                (0, "dashboard"),
                (1, "rules"),
                (2, "proxies"),
                (3, "connections"),
                (4, "settings"),
                (5, "logs"),
            ] {
                ui.set_page(page);
                ui.set_settings_section(0);
                save(
                    &main_adapter,
                    &destination.join(format!("review-{name}-{theme}-{size}.png")),
                )?;
            }
            ui.set_page(4);
            ui.set_settings_section(2);
            save(
                &main_adapter,
                &destination.join(format!("review-settings-2-{theme}-{size}.png")),
            )?;
            ui.set_page(6);
            let xray = ui.global::<XrayModule>();
            for section in 0..7 {
                xray.set_section(section);
                xray.set_pending(false);
                save(
                    &main_adapter,
                    &destination.join(format!("review-xray-{section}-{theme}-{size}.png")),
                )?;
            }
        }
    }
    ui.hide()?;
    println!("Headless fixture PNGs: {}", destination.display());
    Ok(())
}

#[cfg(windows)]
fn xray_previews(ui: &MainWindow, adapter: &MemoryWindow, destination: &Path) -> Result<()> {
    ui.set_page(4);
    ui.set_settings_section(2);
    save(adapter, &destination.join("xray-modules.png"))?;

    let xray = ui.global::<XrayModule>();
    xray.set_installed(true);
    xray.set_version("v26.10.21".into());
    xray.set_error("Xray exited before its local SOCKS port was ready".into());
    save(adapter, &destination.join("xray-modules-installed.png"))?;
    xray.set_error("".into());
    xray.set_status("Preview · sample data".into());
    xray.set_running(true);
    xray.set_uptime("00:21:16".into());
    xray.set_connection_count(38);
    xray.set_upload("29".into());
    xray.set_download("9".into());
    xray.set_profiles(model(vec![XrayProfileRow {
        id: "primary".into(),
        name: "Primary".into(),
        summary: "VLESS · vpn.example.test:443".into(),
        active: true,
    }]));
    xray.set_selected_profile(XrayProfileRow {
        id: "primary".into(),
        name: "Primary".into(),
        summary: "VLESS · vpn.example.test:443".into(),
        active: true,
    });
    xray.set_subscriptions(model(vec![XraySubscriptionGroup {
        id: "sample-source".into(),
        name: "Subscription 1".into(),
        profiles: model(vec![
            XrayProfileRow {
                id: "backup".into(),
                name: "Backup".into(),
                summary: "VLESS · backup.example.test:443".into(),
                active: false,
            },
            XrayProfileRow {
                id: "regional".into(),
                name: "Regional".into(),
                summary: "VLESS · regional.example.test:443".into(),
                active: false,
            },
        ]),
    }]));
    xray.set_dns("https://resolver.example.test/dns-query".into());
    xray.set_hosts(model(vec![
        XrayHostRow {
            host: "backup.example.test".into(),
            address: "—".into(),
        },
        XrayHostRow {
            host: "regional.example.test".into(),
            address: "203.0.113.7".into(),
        },
        XrayHostRow {
            host: "vpn.example.test".into(),
            address: "203.0.113.6".into(),
        },
    ]));
    xray.set_geo_ip_selected(model(vec!["ru".into(), "private".into()]));
    xray.set_geo_site_selected(model(vec!["category-ru".into()]));
    xray.set_geo_site_query("cate".into());
    xray.set_geo_site_suggestions(model(vec![
        "category-ads-all".into(),
        "category-gov-ru".into(),
    ]));
    let defaults = true_proxy::xray::profile::Settings::default();
    xray.set_geo_ip_url(defaults.geoip_url.into());
    xray.set_geo_site_url(defaults.geosite_url.into());
    xray.set_geo_refresh_hours(defaults.geo_refresh_hours.to_string().into());
    xray.set_geo_status("Both databases are ready".into());
    xray.set_connections(model(vec![
        XrayConnectionRow {
            time: "14:32:04".into(),
            protocol: "TCP".into(),
            destination: "203.0.113.3:443".into(),
            observed_domain: "example.org".into(),
            source: "127.0.0.1:52071".into(),
            route: "VLESS".into(),
            detail: "Accepted".into(),
        },
        XrayConnectionRow {
            time: "14:32:01".into(),
            protocol: "UDP".into(),
            destination: "198.51.100.17:3478".into(),
            observed_domain: "".into(),
            source: "127.0.0.1:52069".into(),
            route: "Direct".into(),
            detail: "Accepted".into(),
        },
    ]));
    xray.set_connection_total(2);
    xray.set_log_total(3);
    xray.set_log_visible_count(3);
    xray.set_log_recording(true);
    xray.set_log_text(
        "14:10:48  INF  [Core] Xray started\n\
         14:32:01  INF  [Access] UDP 198.51.100.17:3478 · Direct\n\
         14:32:04  INF  [Access] TCP example.org:443 · VLESS"
            .into(),
    );
    ui.set_page(6);
    for (section, name) in [
        "dashboard",
        "profiles",
        "general",
        "dns",
        "fallbacks",
        "connections",
        "logs",
    ]
    .iter()
    .enumerate()
    {
        xray.set_section(section as i32);
        xray.set_pending(*name == "general");
        if *name == "general" {
            xray.set_port("2082".into());
        }
        save(adapter, &destination.join(format!("xray-{name}.png")))?;
    }
    xray.set_section(1);
    xray.set_hpwnr_required(true);
    xray.set_profile_input("v2raytun://crypt/example-fixture".into());
    save(adapter, &destination.join("hpwnr-import-confirmation.png"))?;
    xray.set_hpwnr_required(false);
    xray.set_profile_input("".into());
    xray.set_hpwnr_installed(true);
    xray.set_hpwnr_version("1.0.3".into());
    ui.set_page(4);
    ui.set_settings_section(2);
    save(adapter, &destination.join("hpwnr-installed.png"))?;
    xray.set_hpwnr_installed(false);
    xray.set_hpwnr_version("".into());
    ui.set_page(0);
    ui.set_update_available(true);
    ui.set_update_version("999.0.0".into());
    ui.set_update_text(
        "Install and restart automatically. Active proxy connections will close briefly.".into(),
    );
    save(
        adapter,
        &destination.join("update-while-routing-active.png"),
    )?;
    ui.set_update_available(false);
    Ok(())
}
