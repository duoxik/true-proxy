use std::sync::atomic::Ordering;
use true_proxy::{
    config::{Action, DnsPolicy, Protocol, Rule},
    connections::{Info, Status},
    engine::{LogLevel, LogSource, Statistics},
};

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
