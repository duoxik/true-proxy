//! A managed Xray instance with one loopback SOCKS inbound and one VLESS node.

use crate::config::Protocol;
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    io::{self, BufRead},
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use self::windows::Child;

const ROW_LIMIT: usize = 256;
const LINE_LIMIT: usize = 2048;
const INBOUND: &str = "socks";
const TUNNEL: &str = "vless";
const DNS_INBOUND: &str = "module-dns";
const DNS_TUNNEL: &str = "vless-dns";
const DIRECT: &str = "direct";

pub struct Settings<'a> {
    pub socks_port: u16,
    pub upstream: &'a str,
    pub upstream_port: u16,
    pub upstream_ip: Option<IpAddr>,
    pub outbound: &'a Value,
    pub dns_servers: &'a [String],
    pub direct_domains: &'a [String],
    pub direct_ips: &'a [String],
    pub geo_directory: &'a Path,
}

#[derive(Clone)]
pub struct LogLine {
    pub time: String,
    pub level: String,
    pub message: String,
    pub access: bool,
}

#[derive(Clone)]
pub struct ConnectionEvent {
    pub time: String,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub route: String,
    pub status: String,
}

#[derive(Clone, Copy, Default)]
pub struct Stats {
    pub accepted: u64,
    pub rejected: u64,
    pub proxied: u64,
    pub direct: u64,
}

#[derive(Default)]
struct ActivityState {
    stats: Stats,
    logs: VecDeque<LogLine>,
    connections: VecDeque<ConnectionEvent>,
}

#[derive(Default)]
pub struct Activity {
    recording: AtomicBool,
    state: Mutex<ActivityState>,
}

impl Activity {
    pub fn set_recording(&self, enabled: bool) {
        self.recording.store(enabled, Ordering::Release);
    }

    pub fn recording(&self) -> bool {
        self.recording.load(Ordering::Acquire)
    }

    pub fn stats(&self) -> Stats {
        self.state.lock().unwrap().stats
    }

    pub fn logs(&self) -> Vec<LogLine> {
        self.state.lock().unwrap().logs.iter().cloned().collect()
    }

    pub fn connections(&self) -> Vec<ConnectionEvent> {
        self.state
            .lock()
            .unwrap()
            .connections
            .iter()
            .rev()
            .cloned()
            .collect()
    }

    pub fn clear_logs(&self) {
        self.state.lock().unwrap().logs.clear();
    }

    pub fn clear_connections(&self) {
        self.state.lock().unwrap().connections.clear();
    }

    fn new_session(&self) {
        let mut state = self.state.lock().unwrap();
        state.stats = Stats::default();
        state.connections.clear();
    }

    fn receive(&self, line: &str) {
        let (time, message) = split_time(line);
        let event = access_event(time, message);
        let access = event.is_some();
        let recording = self.recording();
        if !access && !recording {
            return;
        }
        let mut state = self.state.lock().unwrap();
        if let Some(event) = event {
            if event.status == "Accepted" {
                state.stats.accepted = state.stats.accepted.saturating_add(1);
                if event.route == "Direct" {
                    state.stats.direct = state.stats.direct.saturating_add(1);
                } else if event.route == "VLESS" {
                    state.stats.proxied = state.stats.proxied.saturating_add(1);
                }
            } else {
                state.stats.rejected = state.stats.rejected.saturating_add(1);
            }
            push_bounded(&mut state.connections, event);
        }
        if recording {
            let level = if message.contains("[Error]") {
                "Error"
            } else if message.contains("[Warning]") {
                "Warning"
            } else if message.contains("[Debug]") {
                "Debug"
            } else {
                "Info"
            };
            push_bounded(
                &mut state.logs,
                LogLine {
                    time: time.to_owned(),
                    level: level.to_owned(),
                    message: message.to_owned(),
                    access,
                },
            );
        }
    }
}

fn push_bounded<T>(rows: &mut VecDeque<T>, row: T) {
    if rows.len() == ROW_LIMIT {
        rows.pop_front();
    }
    rows.push_back(row);
}

fn split_time(line: &str) -> (&str, &str) {
    let mut parts = line.splitn(3, ' ');
    let date = parts.next().unwrap_or_default();
    let time = parts.next().unwrap_or_default();
    if date.as_bytes().get(4) == Some(&b'/') && time.as_bytes().get(2) == Some(&b':') {
        return (time, parts.next().unwrap_or_default());
    }
    ("", line)
}

fn access_event(time: &str, message: &str) -> Option<ConnectionEvent> {
    let mut parts = message.strip_prefix("from ")?.splitn(4, ' ');
    let source = parts.next()?;
    let status = match parts.next()? {
        "accepted" => "Accepted",
        "rejected" => "Rejected",
        _ => return None,
    };
    let target = parts.next()?;
    // The core logs a rejected handshake with no destination when a local
    // checker disconnects after negotiating. Keep that diagnostic in Logs.
    if target.is_empty() {
        return None;
    }
    let detour = parts
        .next()
        .and_then(|tail| tail.strip_prefix('['))
        .and_then(|tail| tail.split_once(']'))
        .map(|(route, _)| route);
    let route = match detour.and_then(|route| route.split_ascii_whitespace().last()) {
        Some(DIRECT) => "Direct",
        Some(TUNNEL) => "VLESS",
        Some(DNS_TUNNEL) => return None,
        _ => "—",
    };
    let (protocol, destination) = match target.split_once(':') {
        Some(("tcp", destination)) => ("TCP", destination),
        Some(("udp", destination)) => ("UDP", destination),
        _ => ("—", target),
    };
    Some(ConnectionEvent {
        time: time.to_owned(),
        source: source.to_owned(),
        destination: destination.to_owned(),
        protocol: protocol.to_owned(),
        route: route.to_owned(),
        status: status.to_owned(),
    })
}

fn read_output(mut reader: impl BufRead, activity: &Activity, secret: &str) -> io::Result<()> {
    let mut line = Vec::with_capacity(LINE_LIMIT);
    loop {
        let bytes = reader.fill_buf()?;
        if bytes.is_empty() {
            break;
        }
        let newline = bytes.iter().position(|&byte| byte == b'\n');
        let count = newline.unwrap_or(bytes.len());
        let capacity = LINE_LIMIT - line.len();
        line.extend_from_slice(&bytes[..count.min(capacity)]);
        reader.consume(count + usize::from(newline.is_some()));
        if newline.is_some() {
            let text = String::from_utf8_lossy(&line);
            if text.contains(secret) {
                activity.receive(text.trim_end().replace(secret, "[redacted]").as_str());
            } else {
                activity.receive(text.trim_end());
            }
            line.clear();
        }
    }
    Ok(())
}

fn upstream(settings: &Settings<'_>) -> Result<SocketAddr> {
    ensure!(
        settings.socks_port != 0,
        "Choose a SOCKS port between 1 and 65535"
    );
    ensure!(
        settings.upstream_port != 0,
        "The VLESS server port is invalid"
    );
    if let Some(ip) = settings.upstream_ip {
        return Ok(SocketAddr::new(ip, settings.upstream_port));
    }
    (settings.upstream, settings.upstream_port)
        .to_socket_addrs()
        .context("Windows could not resolve the VLESS server")?
        .next()
        .context("Windows returned no address for the VLESS server")
}

fn configuration(settings: &Settings<'_>, address: SocketAddr) -> Result<(Value, String)> {
    let input = settings.outbound;
    let source = &input["settings"];
    let transport = &input["streamSettings"];
    let tls = &transport["tlsSettings"];
    ensure!(
        input["protocol"] == "vless"
            && matches!(transport["network"].as_str(), Some("raw" | "tcp"))
            && transport["security"] == "tls",
        "This version supports VLESS over RAW/TCP + TLS"
    );
    ensure!(
        source["encryption"] == "none",
        "This version supports VLESS encryption set to none with TLS"
    );
    let id = source["id"]
        .as_str()
        .filter(|id| !id.is_empty() && id.len() <= 64)
        .context("The VLESS profile has no valid ID")?;
    let flow = source["flow"].as_str().unwrap_or("");
    ensure!(
        matches!(flow, "" | "xtls-rprx-vision" | "xtls-rprx-vision-udp443"),
        "Unsupported VLESS flow"
    );
    let name = tls["serverName"].as_str().unwrap_or(settings.upstream);
    ensure!(!name.is_empty(), "The VLESS profile has no TLS server name");
    let mut tls_settings = json!({ "serverName": name });
    if let Some(fingerprint) = tls["fingerprint"].as_str() {
        tls_settings["fingerprint"] = json!(fingerprint);
    }
    if let Some(alpn) = tls["alpn"].as_array() {
        ensure!(
            alpn.len() <= 8
                && alpn
                    .iter()
                    .all(|value| value.as_str().is_some_and(|p| p.len() <= 64)),
            "Invalid TLS ALPN list"
        );
        tls_settings["alpn"] = json!(alpn);
    }
    let custom_dns = !settings.dns_servers.is_empty();
    ensure!(
        settings.dns_servers.len() <= 8,
        "Choose at most eight DNS resolvers"
    );
    for server in settings.dns_servers {
        ensure!(
            server.parse::<IpAddr>().is_ok()
                || (server.starts_with("https://")
                    && server.len() <= 1024
                    && server[8..].contains('/')
                    && !server.contains(['@', '#'])
                    && !server.chars().any(char::is_whitespace)),
            "Enter an IP address or HTTPS DNS resolver URL"
        );
    }
    ensure!(
        settings
            .direct_domains
            .iter()
            .all(|tag| geo_tag(tag, "geosite:")),
        "Domain fallback must use geosite tags"
    );
    ensure!(
        settings.direct_ips.iter().all(|tag| geo_tag(tag, "geoip:")),
        "IP fallback must use geoip tags"
    );
    let has_direct = !settings.direct_domains.is_empty() || !settings.direct_ips.is_empty();
    let mut inbound = json!({
        "tag": INBOUND,
        "listen": "127.0.0.1",
        "port": settings.socks_port,
        "protocol": "socks",
        "settings": { "auth": "noauth", "udp": true, "ip": "127.0.0.1" },
    });
    if !settings.direct_domains.is_empty() {
        inbound["sniffing"] = json!({
            "enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true
        });
    }
    let vless = json!({
        "tag": TUNNEL,
        "protocol": "vless",
        "targetStrategy": if custom_dns { "ForceIP" } else { "AsIs" },
        "settings": {
            "address": address.ip(), "port": address.port(), "id": id,
            "encryption": "none", "flow": flow,
        },
        "streamSettings": {
            "network": "raw", "security": "tls", "tlsSettings": tls_settings,
        },
        "mux": { "enabled": false },
    });
    let mut outbounds = vec![vless.clone()];
    let mut routes = Vec::new();
    if custom_dns {
        let mut dns_outbound = vless;
        dns_outbound["tag"] = json!(DNS_TUNNEL);
        // A DNS resolver hostname is resolved by the VPN server. Resolving it
        // through the local built-in DNS again would recurse.
        dns_outbound["targetStrategy"] = json!("AsIs");
        outbounds.push(dns_outbound);
        routes.push(
            json!({ "type": "field", "inboundTag": [DNS_INBOUND], "outboundTag": DNS_TUNNEL }),
        );
    }
    if has_direct {
        outbounds.push(json!({
            "tag": DIRECT, "protocol": "freedom",
            "streamSettings": { "sockopt": { "domainStrategy": if custom_dns { "ForceIP" } else { "AsIs" } } }
        }));
        for (field, tags) in [
            ("domain", settings.direct_domains),
            ("ip", settings.direct_ips),
        ] {
            if !tags.is_empty() {
                let mut rule =
                    json!({ "type": "field", "inboundTag": [INBOUND], "outboundTag": DIRECT });
                rule[field] = json!(tags);
                routes.push(rule);
            }
        }
    }
    let mut config = json!({
        "log": { "loglevel": "info", "access": "", "error": "" },
        "inbounds": [inbound],
        "outbounds": outbounds,
        "routing": { "domainStrategy": "AsIs", "rules": routes },
    });
    if custom_dns {
        config["dns"] = json!({ "tag": DNS_INBOUND, "servers": settings.dns_servers });
    }
    Ok((config, id.to_owned()))
}

fn geo_tag(tag: &str, prefix: &str) -> bool {
    tag.strip_prefix(prefix).is_some_and(|code| {
        !code.is_empty()
            && code.len() <= 100
            && code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
    })
}

#[cfg(windows)]
struct Allowance {
    generation: u64,
    identity: Arc<windows::Identity>,
    upstream: SocketAddr,
    geo_direct: bool,
}

#[derive(Default)]
pub struct Bypass {
    #[cfg(windows)]
    pid: std::sync::atomic::AtomicU32,
    #[cfg(windows)]
    generation: std::sync::atomic::AtomicU64,
    #[cfg(windows)]
    sequence: std::sync::atomic::AtomicU64,
    #[cfg(windows)]
    active: Mutex<Option<Allowance>>,
}

impl Bypass {
    pub fn generation(&self) -> u64 {
        #[cfg(windows)]
        {
            self.generation.load(Ordering::Acquire)
        }
        #[cfg(not(windows))]
        {
            0
        }
    }

    pub fn classify(
        &self,
        pid: u32,
        destination: SocketAddr,
        protocol: Protocol,
    ) -> Option<(u64, bool)> {
        #[cfg(windows)]
        {
            if pid == 0 || self.pid.load(Ordering::Acquire) != pid {
                return None;
            }
            let active = self.active.lock().unwrap();
            let entry = active
                .as_ref()
                .filter(|entry| entry.identity.pid() == pid)?;
            let allowed = entry.identity.alive()
                && ((destination == entry.upstream && protocol == Protocol::Tcp)
                    || (entry.geo_direct && matches!(protocol, Protocol::Tcp | Protocol::Udp)));
            Some((entry.generation, allowed))
        }
        #[cfg(not(windows))]
        {
            let _ = (pid, destination, protocol);
            None
        }
    }

    #[cfg(windows)]
    fn activate(&self, identity: Arc<windows::Identity>, upstream: SocketAddr, geo_direct: bool) {
        let pid = identity.pid();
        let generation = self
            .sequence
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
            .max(1);
        *self.active.lock().unwrap() = Some(Allowance {
            generation,
            identity,
            upstream,
            geo_direct,
        });
        self.generation.store(generation, Ordering::Release);
        self.pid.store(pid, Ordering::Release);
    }

    #[cfg(windows)]
    fn retire(&self, identity: &Arc<windows::Identity>) {
        let mut active = self.active.lock().unwrap();
        if active
            .as_ref()
            .is_some_and(|entry| Arc::ptr_eq(&entry.identity, identity))
        {
            self.pid.store(0, Ordering::Release);
            self.generation.store(0, Ordering::Release);
            *active = None;
        }
    }
}

pub struct Runtime {
    #[cfg(windows)]
    child: Child,
    #[cfg(windows)]
    bypass: Arc<Bypass>,
    started: Instant,
}

impl Runtime {
    pub fn start(
        installed: &super::assets::Installed,
        settings: Settings<'_>,
        bypass: Arc<Bypass>,
        activity: Arc<Activity>,
    ) -> Result<Self> {
        #[cfg(windows)]
        {
            let address = upstream(&settings)?;
            let (config, secret) = configuration(&settings, address)?;
            let child = Child::spawn(installed, settings.geo_directory, &activity, secret)?;
            bypass.activate(
                child.identity().clone(),
                address,
                !settings.direct_domains.is_empty() || !settings.direct_ips.is_empty(),
            );
            let mut runtime = Self {
                child,
                bypass,
                started: Instant::now(),
            };
            runtime.child.start(serde_json::to_vec(&config)?)?;
            runtime
                .child
                .wait_socks(settings.socks_port, Duration::from_secs(5))?;
            Ok(runtime)
        }
        #[cfg(not(windows))]
        {
            let _ = (installed, settings, bypass, activity);
            anyhow::bail!("The Xray module is available on Windows")
        }
    }

    pub fn running(&mut self) -> Result<bool> {
        #[cfg(windows)]
        {
            if self.child.identity().alive() {
                return Ok(true);
            }
            self.bypass.retire(self.child.identity());
        }
        Ok(false)
    }

    pub fn started_at(&self) -> Instant {
        self.started
    }

    pub fn stop(&mut self) {
        #[cfg(windows)]
        {
            self.bypass.retire(self.child.identity());
            self.child.stop();
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_pins_server_and_routes_internal_dns_before_geo_rules() {
        let profile = json!({
            "protocol": "vless",
            "settings": {"id": "fixture", "encryption": "none", "flow": "xtls-rprx-vision"},
            "streamSettings": {
                "network": "raw", "security": "tls",
                "tlsSettings": {"serverName": "node.example", "allowInsecure": true}
            },
        });
        let settings = Settings {
            socks_port: 2081,
            upstream: "node.example",
            upstream_port: 443,
            upstream_ip: Some("192.0.2.1".parse().unwrap()),
            outbound: &profile,
            dns_servers: &["https://dns.example/dns-query".into()],
            direct_domains: &["geosite:category-ru".into()],
            direct_ips: &["geoip:ru".into()],
            geo_directory: Path::new("."),
        };
        let (value, _) = configuration(&settings, upstream(&settings).unwrap()).unwrap();
        assert_eq!(value["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(value["inbounds"][0]["settings"]["udp"], true);
        assert_eq!(value["outbounds"][0]["settings"]["address"], "192.0.2.1");
        let tls = &value["outbounds"][0]["streamSettings"]["tlsSettings"];
        assert_eq!(tls["serverName"], "node.example");
        assert!(tls.get("allowInsecure").is_none());
        assert_eq!(value["outbounds"][1]["targetStrategy"], "AsIs");
        assert_eq!(
            value["routing"]["rules"][0]["inboundTag"],
            json!([DNS_INBOUND])
        );
        assert_eq!(value["routing"]["rules"][1]["outboundTag"], DIRECT);
    }

    #[test]
    fn logs_and_connection_events_are_bounded_and_independent() {
        let activity = Activity::default();
        for _ in 0..300 {
            activity.receive("2026/01/01 12:34:56.123456 from tcp:127.0.0.1:1 accepted tcp:example.test:443 [socks -> vless]");
        }
        assert_eq!(activity.stats().accepted, 300);
        assert_eq!(activity.stats().proxied, 300);
        assert_eq!(activity.connections().len(), 256);
        assert!(activity.logs().is_empty());
        activity.set_recording(true);
        activity.receive("2026/01/01 12:34:56.123456 [Warning] module");
        assert_eq!(activity.logs()[0].level, "Warning");
        activity.clear_connections();
        assert!(activity.connections().is_empty());
        assert_eq!(activity.stats().accepted, 300);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires a verified official Windows x64 Xray fixture"]
    fn native_xray_opens_owned_loopback_socks_and_stops() {
        use std::{
            io::{Read, Write},
            net::{Ipv4Addr, TcpListener, TcpStream},
            thread,
        };

        let fixture = std::env::var_os("TRUE_PROXY_XRAY_FIXTURE_EXE")
            .expect("set TRUE_PROXY_XRAY_FIXTURE_EXE to a disposable official xray.exe");
        let sha256 = std::env::var("TRUE_PROXY_XRAY_FIXTURE_SHA256")
            .expect("set TRUE_PROXY_XRAY_FIXTURE_SHA256 to the fixture checksum");
        let installed = super::super::assets::Installed {
            version: "test".into(),
            executable: fixture.into(),
            sha256,
        };
        let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let profile = json!({
            "protocol": "vless",
            "settings": {"id": "fixture", "encryption": "none", "flow": "xtls-rprx-vision"},
            "streamSettings": {
                "network": "raw", "security": "tls",
                "tlsSettings": {"serverName": "localhost"}
            },
        });
        let settings = Settings {
            socks_port: port,
            upstream: "localhost",
            upstream_port: 9,
            upstream_ip: Some(Ipv4Addr::LOCALHOST.into()),
            outbound: &profile,
            dns_servers: &[],
            direct_domains: &[],
            direct_ips: &[],
            geo_directory: installed.executable.parent().unwrap(),
        };
        let bypass = Arc::new(Bypass::default());
        let activity = Arc::new(Activity::default());
        activity.set_recording(true);
        let mut runtime = Runtime::start(&installed, settings, bypass.clone(), activity.clone())
            .unwrap_or_else(|error| {
                let log: Vec<_> = activity
                    .logs()
                    .into_iter()
                    .map(|line| line.message)
                    .collect();
                panic!("{error:#}\n{}", log.join("\n"));
            });
        assert!(runtime.running().unwrap());
        let pid = runtime.child.identity().pid();
        let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        assert_eq!(
            bypass.classify(pid, endpoint, Protocol::Tcp),
            Some((bypass.generation(), true))
        );
        assert_eq!(
            bypass.classify(pid, endpoint, Protocol::Udp),
            Some((bypass.generation(), false))
        );
        assert_eq!(activity.stats().accepted, 0);
        let mut socks = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        socks
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socks.write_all(&[5, 1, 0]).unwrap();
        let mut method = [0; 2];
        socks.read_exact(&mut method).unwrap();
        assert_eq!(method, [5, 0]);
        // This request can only dial the configured loopback VLESS endpoint.
        // The destination label below is from documentation space.
        socks
            .write_all(&[5, 1, 0, 1, 192, 0, 2, 9, 1, 187])
            .unwrap();
        let until = Instant::now() + Duration::from_secs(2);
        while activity.stats().accepted == 0 && Instant::now() < until {
            thread::sleep(Duration::from_millis(10));
        }
        let events = activity.connections();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].destination, "192.0.2.9:443");
        assert_eq!(events[0].route, "VLESS");
        assert_eq!(events[0].protocol, "TCP");
        assert_eq!(activity.stats().proxied, 1);
        drop(socks);
        runtime.stop();
        assert!(!runtime.running().unwrap());
        assert_eq!(bypass.generation(), 0);
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
    }
}
