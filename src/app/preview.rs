use std::sync::atomic::Ordering;
use true_proxy::{
    config::{Action, DnsPolicy, Protocol, Rule},
    connections::{Info, Status},
    engine::{LogLevel, LogSource, Statistics},
};

/// Explicit fixtures for the isolated local UI preview; never a core process.
pub(crate) fn populate_xray(ui: &crate::MainWindow) {
    use crate::{XrayModule, XrayProfileRow, XraySubscriptionGroup};
    use slint::ComponentHandle;
    let xray = ui.global::<XrayModule>();
    let primary = XrayProfileRow {
        id: "preview-primary".into(),
        name: "Primary tunnel".into(),
        summary: "VLESS · vpn.example.test:443".into(),
        active: true,
    };
    xray.set_installed(true);
    xray.set_version("26.10.31".into());
    xray.set_hpwnr_installed(true);
    xray.set_hpwnr_version("1.0.3".into());
    xray.set_selected_profile(primary.clone());
    xray.set_profiles(super::model(vec![primary]));
    xray.set_subscriptions(super::model(vec![XraySubscriptionGroup {
        id: "preview-subscription".into(),
        name: "Subscription 1".into(),
        profiles: super::model(vec![XrayProfileRow {
            id: "preview-backup".into(),
            name: "Backup tunnel".into(),
            summary: "VLESS · backup.example.test:443".into(),
            active: false,
        }]),
    }]));
    let weak = ui.as_weak();
    xray.on_activate_profile(move |id| {
        use slint::Model;
        let Some(ui) = weak.upgrade() else { return };
        let xray = ui.global::<XrayModule>();
        let mut selected = XrayProfileRow::default();
        let mut select = |mut row: XrayProfileRow| {
            row.active = row.id == id;
            if row.active {
                selected = row.clone();
            }
            row
        };
        let manual = xray.get_profiles().iter().map(&mut select).collect();
        let groups = xray
            .get_subscriptions()
            .iter()
            .map(|mut group| {
                group.profiles = super::model(group.profiles.iter().map(&mut select).collect());
                group
            })
            .collect();
        if selected.id.is_empty() {
            return;
        }
        xray.set_profiles(super::model(manual));
        xray.set_subscriptions(super::model(groups));
        xray.set_selected_profile(selected);
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
