use std::sync::atomic::Ordering;
use true_proxy::{
    config::{Action, DnsPolicy, Protocol, Rule},
    connections::{Info, Status},
    engine::{LogLevel, LogSource, Statistics},
};

/// Explicit fixtures for the isolated local UI preview; never a core process.
#[cfg(windows)]
pub(crate) fn populate_xray(ui: &crate::MainWindow) {
    use crate::XrayModule;
    use slint::ComponentHandle;
    use std::{cell::RefCell, rc::Rc};
    use true_proxy::xray::profile::Settings;
    let xray = ui.global::<XrayModule>();
    let settings: Settings = serde_json::from_value(serde_json::json!({
        "ports": [
            {"id":"default","name":"Default","number":2081,"is_default":true},
            {"id":"us","name":"US","number":2082,"is_default":false}
        ],
        "subscriptions": [
            {"id":"preview-subscription", "protected_url":""},
            {"id":"preview-us", "protected_url":""}
        ],
        "profiles":[
            {"id":"preview-primary","name":"Primary tunnel","host":"vpn.example.test","port":443,"protected":"","subscription":null,"enabled":true,"port_id":"default"},
            {"id":"preview-backup","name":"Backup tunnel","host":"backup.example.test","port":443,"protected":"","subscription":"preview-subscription","port_id":"us"},
            {"id":"preview-us-east","name":"US East","host":"us.example.test","port":443,"protected":"","subscription":"preview-us","port_id":"us"}
        ]
    })).expect("valid preview profiles");
    let settings = Rc::new(RefCell::new(settings));
    xray.set_installed(true);
    xray.set_version("26.10.31".into());
    xray.set_hpwnr_installed(true);
    xray.set_hpwnr_version("1.0.3".into());
    fn refresh(ui: &crate::MainWindow, settings: &Settings) {
        super::xray::show_profiles(ui, settings);
        super::xray::show_preview_ports(ui, settings, None);
    }
    refresh(ui, &settings.borrow());
    let model = settings.clone();
    let weak = ui.as_weak();
    xray.on_settings_edited(move || {
        let Some(ui) = weak.upgrade() else { return };
        let xray = ui.global::<XrayModule>();
        match super::xray::parse_dns_draft(xray.get_dns().as_str()) {
            Ok(dns) => {
                let mut settings = model.borrow_mut();
                settings.dns = dns;
                xray.set_settings_error("".into());
            }
            Err(error) => xray.set_settings_error(error.to_string().into()),
        }
    });
    let model = settings.clone();
    let weak = ui.as_weak();
    let change_profile = Rc::new(
        move |id: slint::SharedString, port: Option<slint::SharedString>| {
            let Some(ui) = weak.upgrade() else { return };
            let mut settings = model.borrow_mut();
            let result = match port {
                Some(port) => settings.set_profile_port(&id, &port),
                None => settings.toggle_profile(&id),
            };
            match result {
                Ok(previous) => {
                    if let Some(previous) = previous {
                        let selected = settings
                            .profiles
                            .iter()
                            .find(|p| p.id == id.as_str())
                            .unwrap();
                        let port = settings.port(&selected.port_id).unwrap();
                        super::show_toast(
                            &ui,
                            format!("Replaced {previous} on {}", port.name),
                            false,
                        );
                    }
                    refresh(&ui, &settings);
                }
                Err(error) => ui
                    .global::<XrayModule>()
                    .set_error(error.to_string().into()),
            }
        },
    );
    let toggle = change_profile.clone();
    xray.on_activate_profile(move |id| toggle(id, None));
    xray.on_assign_profile_port(move |id, port| change_profile(id, Some(port)));
    let model = settings.clone();
    super::xray::wire_port_editor(ui, move |ui, edit, revision| {
        let mut settings = model.borrow_mut();
        let result = edit.apply(&mut settings, &[]);
        let xray = ui.global::<XrayModule>();
        if result.is_ok() {
            refresh(ui, &settings);
        }
        drop(settings);
        xray.invoke_finish_port_edit(
            edit.id.into(),
            edit.number,
            revision,
            result
                .err()
                .map_or_else(String::new, |e| e.to_string())
                .into(),
        );
        true
    });
    let model = settings.clone();
    let weak = ui.as_weak();
    xray.on_add_port(move || {
        let Some(ui) = weak.upgrade() else { return };
        let mut settings = model.borrow_mut();
        match settings.add_port(&[]) {
            Ok(_) => refresh(&ui, &settings),
            Err(error) => ui
                .global::<XrayModule>()
                .set_error(error.to_string().into()),
        }
    });
    let model = settings.clone();
    let weak = ui.as_weak();
    xray.on_remove_port(move |id| {
        let Some(ui) = weak.upgrade() else { return };
        let mut settings = model.borrow_mut();
        if let Err(error) = settings.remove_port(&id) {
            super::xray::show_preview_ports(&ui, &settings, Some(&(id.into(), error.to_string())));
        } else {
            refresh(&ui, &settings);
        }
    });
    let weak = ui.as_weak();
    xray.on_remove_profile(move |id| {
        if let Some(ui) = weak.upgrade() {
            let mut settings = settings.borrow_mut();
            settings.remove_profile(&id);
            refresh(&ui, &settings);
        }
    });
    let weak = ui.as_weak();
    xray.on_toggle(move || {
        if let Some(ui) = weak.upgrade() {
            ui.global::<XrayModule>().set_error(
                "Xray is disabled in this UI preview. No core process is started.".into(),
            );
        }
    });
    let weak = ui.as_weak();
    xray.on_import_profile(move |input| {
        if let Some(ui) = weak.upgrade() {
            let xray = ui.global::<XrayModule>();
            xray.set_hpwnr_required(
                true_proxy::xray::hpwnr::encrypted(&input) && !xray.get_hpwnr_installed(),
            );
            if !xray.get_hpwnr_required() {
                xray.set_error("Profile imports are disabled in this UI preview.".into());
            }
        }
    });
    let weak = ui.as_weak();
    xray.on_install_hpwnr(move || {
        if let Some(ui) = weak.upgrade() {
            ui.global::<XrayModule>()
                .set_hpwnr_error("Module downloads are disabled in this UI preview.".into());
        }
    });
    let weak = ui.as_weak();
    xray.on_confirm_hpwnr(move || {
        if let Some(ui) = weak.upgrade() {
            let xray = ui.global::<XrayModule>();
            xray.set_hpwnr_required(false);
            xray.invoke_install_hpwnr();
        }
    });
    let weak = ui.as_weak();
    xray.on_cancel_hpwnr(move || {
        if let Some(ui) = weak.upgrade() {
            ui.global::<XrayModule>().set_hpwnr_required(false);
        }
    });
    let weak = ui.as_weak();
    xray.on_check_hpwnr_updates(move || {
        if let Some(ui) = weak.upgrade() {
            ui.global::<XrayModule>()
                .set_hpwnr_update_status("Update checks are disabled in this UI preview.".into());
        }
    });
    let weak = ui.as_weak();
    xray.on_update_hpwnr(move || {
        if let Some(ui) = weak.upgrade() {
            ui.global::<XrayModule>().invoke_install_hpwnr();
        }
    });
}

#[cfg(not(windows))]
pub(crate) fn populate_xray(_ui: &crate::MainWindow) {}

pub(super) fn populate_logs(stats: &Statistics) {
    use LogLevel::{Error, Info, Verbose};
    use LogSource::{Backend, Connections};
    stats.log(Backend, Info, "", "", "", "UI preview started");
    stats.log(
        Connections,
        Info,
        "firefox.exe",
        "203.0.113.14:443",
        "Local VPN",
        "TCP · Browser · www.example.com",
    );
    stats.log(
        Connections,
        Info,
        "steam.exe",
        "198.51.100.25:27017",
        "Backup Proxy",
        "UDP · Games · relay.example.net",
    );
    stats.log(
        Connections,
        Verbose,
        "firefox.exe",
        "203.0.113.24:443",
        "Local VPN",
        "UDP · Route updated using DNS: media.example.net",
    );
    stats.log(
        Connections,
        Error,
        "steam.exe",
        "198.51.100.28:443",
        "Backup Proxy",
        "Sample SOCKS5 timeout",
    );
}

pub(super) fn sample_rules() -> Vec<Rule> {
    let browser = Rule {
        id: "preview-browser".into(),
        name: "Browser".into(),
        enabled: true,
        process_names: vec!["firefox.exe".into(), "msedge.exe".into()],
        process_paths: Vec::new(),
        domains: Vec::new(),
        domain_suffixes: Vec::new(),
        networks: Vec::new(),
        ports: Vec::new(),
        protocol: Protocol::Both,
        action: Action::Proxy("preview-local".into()),
        dns: DnsPolicy::Inherit,
    };
    let games = Rule {
        id: "preview-games".into(),
        name: "Games".into(),
        process_names: vec!["steam.exe".into()],
        protocol: Protocol::Udp,
        action: Action::Proxy("preview-backup".into()),
        ..browser.clone()
    };
    vec![browser, games]
}

/// Populate the isolated monitor's current connections before it opens.
/// The live journal and network backend never receive these records.
pub(super) fn populate_connections(statistics: &Statistics) {
    use Protocol::{Tcp, Udp};
    use Status::{Active, Blocked, Closed, Closing, Connecting, Failed};

    let mut source_port = 51_240;
    let mut add = |process: &str, pid, route: &str, action: Action, peers: &[Peer]| {
        for peer in peers {
            let info = Info {
                pid,
                process: process.into(),
                source: ([192, 0, 2, 1], source_port).into(),
                destination: (peer.address, peer.port).into(),
                protocol: peer.protocol,
                route: route.into(),
                detail: peer.detail.into(),
                action: action.clone(),
                stamp: 0,
            };
            source_port += 1;
            if peer.status.finished() {
                statistics.activity.completed(info, peer.status);
            } else {
                let _ = statistics.activity.start(info, peer.status);
            }
        }
    };

    add(
        "firefox.exe",
        3580,
        "Local VPN",
        Action::Proxy("preview-local".into()),
        &[
            Peer::new(
                [203, 0, 113, 14],
                443,
                Tcp,
                Active,
                "TCP · Browser · www.example.com",
            ),
            Peer::new(
                [203, 0, 113, 24],
                443,
                Udp,
                Active,
                "UDP · Browser · media.example.net",
            ),
            Peer::new(
                [198, 51, 100, 17],
                443,
                Tcp,
                Connecting,
                "TCP · Browser · DNS name unknown",
            ),
            Peer::new(
                [203, 0, 113, 44],
                443,
                Tcp,
                Closed,
                "TCP · Browser · docs.example.org",
            ),
        ],
    );
    add(
        "steam.exe",
        4640,
        "Backup Proxy",
        Action::Proxy("preview-backup".into()),
        &[
            Peer::new(
                [198, 51, 100, 25],
                27017,
                Udp,
                Active,
                "UDP · Games · relay.example.net",
            ),
            Peer::new(
                [198, 51, 100, 28],
                443,
                Tcp,
                Failed,
                "TCP · Games · DNS name unknown · SOCKS timeout",
            ),
        ],
    );
    add(
        "explorer.exe",
        2068,
        "Direct",
        Action::Direct,
        &[Peer::new(
            [192, 168, 1, 20],
            445,
            Tcp,
            Closing,
            "TCP · Local network",
        )],
    );
    add(
        "updater.exe",
        8192,
        "Block",
        Action::Block,
        &[Peer::new(
            [203, 0, 113, 71],
            443,
            Tcp,
            Blocked,
            "TCP · Block updates · DNS name unknown",
        )],
    );
}

pub(super) fn populate_traffic(statistics: &Statistics) {
    let mut total_uploaded = 0;
    let mut total_downloaded = 0;
    for (name, uploaded, downloaded) in [
        ("firefox.exe", 42 * 1024, 80 * 1024),
        ("steam.exe", 57 * 1024, 91 * 1024 + 512),
    ] {
        let counters = statistics.process(name);
        counters.uploaded.store(uploaded, Ordering::Relaxed);
        counters.downloaded.store(downloaded, Ordering::Relaxed);
        total_uploaded += uploaded;
        total_downloaded += downloaded;
    }
    statistics.uploaded.store(total_uploaded, Ordering::Relaxed);
    statistics
        .downloaded
        .store(total_downloaded, Ordering::Relaxed);
}

struct Peer {
    address: [u8; 4],
    port: u16,
    protocol: Protocol,
    status: Status,
    detail: &'static str,
}

impl Peer {
    const fn new(
        address: [u8; 4],
        port: u16,
        protocol: Protocol,
        status: Status,
        detail: &'static str,
    ) -> Self {
        Self {
            address,
            port,
            protocol,
            status,
            detail,
        }
    }
}
