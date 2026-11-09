//! A managed Xray instance with one loopback SOCKS inbound and one VLESS node.

use crate::{config::Protocol, dns::DomainCache};
use serde_json::{Value, json};
use std::{
    borrow::Cow,
    collections::VecDeque,
    io::{self, BufRead},
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use self::windows::Child;
#[cfg(windows)]
pub(super) use self::windows::run_link_decoder;

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
    pub observed_domain: Option<String>,
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
    starting: bool,
    startup_failure: Option<String>,
}

#[derive(Default)]
pub struct Activity {
    recording: AtomicBool,
    state: Mutex<ActivityState>,
    bypass: Option<Arc<Bypass>>,
}

impl Activity {
    pub fn new(bypass: Arc<Bypass>) -> Self {
        Self {
            bypass: Some(bypass),
            ..Self::default()
        }
    }

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
        state.starting = true;
        state.startup_failure = None;
    }

    fn finish_startup(&self) -> Option<String> {
        let mut state = self.state.lock().unwrap();
        state.starting = false;
        state.startup_failure.take()
    }

    fn receive(&self, line: &str) {
        let (time, message) = split_time(line);
        let event = access_event(time, message).map(|mut event| {
            if event.status == "Accepted"
                && let Ok(address) = event.destination.parse::<SocketAddr>()
                && let Some(bypass) = &self.bypass
            {
                event.observed_domain = bypass.observed_domain(address.ip());
            }
            event
        });
        let access = event.is_some();
        let fatal = message.starts_with("Failed to start:")
            || message.starts_with("panic:")
            || message.starts_with("fatal error:")
            || message.contains("[Error]");
        let recording = self.recording();
        if !access && !recording && !fatal {
            return;
        }
        let mut state = self.state.lock().unwrap();
        if fatal && state.starting {
            state.startup_failure = Some(message.replace(char::is_control, " "));
        }
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
            let level = if fatal {
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
        observed_domain: None,
        protocol: protocol.to_owned(),
        route: route.to_owned(),
        status: status.to_owned(),
    })
}

fn read_output(
    mut reader: impl BufRead,
    activity: &Activity,
    secrets: &[impl AsRef<str>],
) -> io::Result<()> {
    // Read far enough past the display limit to redact credentials crossing it.
    let secrets = || {
        secrets
            .iter()
            .map(AsRef::as_ref)
            .filter(|secret| !secret.is_empty())
    };
    let limit = LINE_LIMIT + secrets().map(str::len).max().unwrap_or(0);
    let mut line = Vec::with_capacity(limit);
    let receive = |line: &[u8]| {
        let text = String::from_utf8_lossy(line);
        let mut end = text.floor_char_boundary(LINE_LIMIT);
        for secret in secrets() {
            if let Some((start, _)) = text
                .match_indices(secret)
                .find(|(start, _)| *start < end && *start + secret.len() > end)
            {
                end = start;
            }
        }
        let mut redacted = Cow::Borrowed(&text[..end]);
        for secret in secrets() {
            if redacted.contains(secret) {
                redacted = Cow::Owned(redacted.replace(secret, "[redacted]"));
            }
        }
        activity.receive(redacted[..redacted.floor_char_boundary(LINE_LIMIT)].trim_end());
    };
    loop {
        let bytes = reader.fill_buf()?;
        if bytes.is_empty() {
            break;
        }
        let newline = bytes.iter().position(|&byte| byte == b'\n');
        let count = newline.unwrap_or(bytes.len());
        let capacity = limit - line.len();
        line.extend_from_slice(&bytes[..count.min(capacity)]);
        reader.consume(count + usize::from(newline.is_some()));
        if newline.is_some() {
            receive(&line);
            line.clear();
        }
    }
    if !line.is_empty() {
        receive(&line);
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
    let ip = settings
        .upstream_ip
        .or_else(|| settings.upstream.parse().ok())
        .context("Refresh VPN server addresses in X-RAY → DNS before starting Xray")?;
    Ok(SocketAddr::new(ip, settings.upstream_port))
}

fn configuration(settings: &Settings<'_>, address: SocketAddr) -> Result<(Value, Vec<String>)> {
    let input = settings.outbound;
    let source = &input["settings"];
    let transport = &input["streamSettings"];
    let security = transport["security"].as_str();
    ensure!(
        input["protocol"] == "vless"
            && matches!(transport["network"].as_str(), Some("raw" | "tcp"))
            && matches!(security, Some("tls" | "reality")),
        "This version supports VLESS over RAW/TCP with TLS or REALITY"
    );
    ensure!(
        source["encryption"] == "none",
        "This version supports VLESS encryption set to none"
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
    let mut secrets = vec![id.to_owned()];
    let stream = if security == Some("reality") {
        let reality: super::profile::RealitySettings =
            serde_json::from_value(transport["realitySettings"].clone())
                .map_err(|_| anyhow::anyhow!("Invalid saved REALITY settings"))?;
        reality.validate()?;
        secrets.extend([reality.password.clone(), reality.mldsa65_verify.clone()]);
        json!({ "network": "raw", "security": "reality", "realitySettings": reality })
    } else {
        let tls = &transport["tlsSettings"];
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
        json!({ "network": "raw", "security": "tls", "tlsSettings": tls_settings })
    };
    let custom_dns = !settings.dns_servers.is_empty();
    super::profile::validate_dns_servers(settings.dns_servers)?;
    ensure!(
        settings
            .direct_domains
            .iter()
            .all(|tag| geo_tag(tag, "geosite")),
        "Domain fallback must use geosite tags"
    );
    ensure!(
        settings.direct_ips.iter().all(|tag| geo_tag(tag, "geoip")),
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
        "streamSettings": stream,
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
    Ok((config, secrets))
}

fn geo_tag(tag: &str, kind: &str) -> bool {
    tag.split_once(':')
        .is_some_and(|(prefix, code)| prefix == kind && super::profile::valid_geo_code(code, kind))
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
    dns_cache: Mutex<Weak<Mutex<DomainCache>>>,
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
    pub fn attach_dns_cache(&self, cache: &Arc<Mutex<DomainCache>>) {
        *self.dns_cache.lock().unwrap() = Arc::downgrade(cache);
    }

    fn observed_domain(&self, ip: IpAddr) -> Option<String> {
        let cache = self.dns_cache.lock().unwrap().upgrade()?;
        let mut names = cache.lock().unwrap().lookup(ip);
        // A shared address is ambiguous even with recent forward DNS answers.
        if names.len() == 1 {
            names.pop().filter(|name| !name.is_empty())
        } else {
            None
        }
    }

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
            windows::check_socks_port(settings.socks_port)?;
            let address = upstream(&settings)?;
            let (config, secrets) = configuration(&settings, address)?;
            let child = Child::spawn(installed, settings.geo_directory, &activity, secrets)?;
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
            let ready = runtime
                .child
                .start(serde_json::to_vec(&config)?)
                .and_then(|()| {
                    runtime
                        .child
                        .wait_socks(settings.socks_port, Duration::from_secs(5))
                });
            if ready.is_err() {
                // Stop drains the child's output after it exits, so a fast
                // failure cannot race ahead of the diagnostic reader.
                runtime.stop();
            }
            let failure = activity.finish_startup();
            if let Err(error) = ready {
                if let Some(failure) = failure {
                    anyhow::bail!("{error}: {failure}");
                }
                return Err(error);
            }
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
    fn imported_reality_profile_reaches_the_tunnel_and_dns_outbounds() {
        let link = "vless://00000000-0000-4000-8000-000000000001@vpn.example.test:443?type=tcp&security=reality&sni=cover.example.test&fp=firefox&pbk=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI&flow=xtls-rprx-vision#Reality";
        let mut profiles = super::super::profile::Settings::default();
        profiles.import(link).unwrap();
        let profile = profiles.selected().unwrap();
        let outbound = profile.outbound().unwrap();
        let address: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let settings = Settings {
            socks_port: 2081,
            upstream: &profile.host,
            upstream_port: profile.port,
            upstream_ip: Some(address.ip()),
            outbound: &outbound,
            dns_servers: &["tcp://192.0.2.53:53".into()],
            direct_domains: &[],
            direct_ips: &[],
            geo_directory: Path::new("."),
        };
        let (config, secrets) = configuration(&settings, address).unwrap();
        for index in [0, 1] {
            let node = &config["outbounds"][index];
            let stream = &node["streamSettings"];
            assert_eq!(node["settings"]["address"], "192.0.2.1");
            assert_eq!(node["settings"]["flow"], "xtls-rprx-vision");
            assert_eq!(stream["security"], "reality");
            assert_eq!(
                stream["realitySettings"]["serverName"],
                "cover.example.test"
            );
            assert_eq!(stream["realitySettings"]["fingerprint"], "firefox");
            assert_eq!(stream["realitySettings"]["password"], secrets[1]);
            assert_eq!(stream["realitySettings"]["shortId"], "");
            assert!(stream.get("tlsSettings").is_none());
        }
    }

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
        let mut settings = Settings {
            socks_port: 2081,
            upstream: "node.example",
            upstream_port: 443,
            upstream_ip: Some("192.0.2.1".parse().unwrap()),
            outbound: &profile,
            dns_servers: &[
                "https://dns.example/dns-query".into(),
                "tcp://192.0.2.53:8853".into(),
            ],
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
        assert_eq!(value["dns"]["servers"][1], "tcp://192.0.2.53:8853");
        assert_eq!(
            value["routing"]["rules"][0]["inboundTag"],
            json!([DNS_INBOUND])
        );
        assert_eq!(value["routing"]["rules"][0]["outboundTag"], DNS_TUNNEL);
        assert_eq!(value["routing"]["rules"][1]["outboundTag"], DIRECT);

        settings.upstream_ip = None;
        assert!(upstream(&settings).is_err());
        settings.upstream = "2001:db8::1";
        assert_eq!(
            upstream(&settings).unwrap(),
            "[2001:db8::1]:443".parse().unwrap()
        );
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

    #[test]
    fn connection_events_use_only_unambiguous_current_dns_observations() {
        fn dns_answer(label: &[u8], ttl: u32, ip: &[u8]) -> Vec<u8> {
            let kind = if ip.len() == 4 { 1 } else { 28 };
            let mut response = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
            response.push(label.len() as u8);
            response.extend_from_slice(label);
            response.extend_from_slice(&[4, b't', b'e', b's', b't', 0, 0, kind, 0, 1]);
            response.extend_from_slice(&[0xc0, 0x0c, 0, kind, 0, 1]);
            response.extend_from_slice(&ttl.to_be_bytes());
            response.extend_from_slice(&[0, ip.len() as u8]);
            response.extend_from_slice(ip);
            response
        }

        let bypass = Arc::new(Bypass::default());
        let activity = Activity::new(bypass.clone());
        let cache = Arc::new(Mutex::new(DomainCache::default()));
        bypass.attach_dns_cache(&cache);
        let address = &[192, 0, 2, 9];
        let observe = |label: &[u8], ttl, ip: &[u8]| {
            cache.lock().unwrap().observe(&dns_answer(label, ttl, ip));
        };
        let connect = |target| {
            activity.receive(&format!(
                "from tcp:127.0.0.1:1 accepted {target} [socks -> vless]"
            ));
            activity.connections().remove(0)
        };

        observe(b"expired", 0, address);
        assert_eq!(connect("tcp:192.0.2.9:443").observed_domain, None);
        observe(b"service", 60, address);
        let event = connect("tcp:192.0.2.9:443");
        assert_eq!(event.destination, "192.0.2.9:443");
        assert_eq!(event.observed_domain.as_deref(), Some("service.test"));
        observe(b"other", 60, address);
        assert_eq!(connect("tcp:192.0.2.9:443").observed_domain, None);

        let ipv6: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let ipv6 = ipv6.octets();
        observe(b"ipv6", 60, &ipv6);
        let event = connect("udp:[2001:db8::1]:443");
        assert_eq!(event.destination, "[2001:db8::1]:443");
        assert_eq!(event.observed_domain.as_deref(), Some("ipv6.test"));

        let named = connect("tcp:requested.test:443");
        assert_eq!(named.destination, "requested.test:443");
        assert_eq!(named.observed_domain, None);
        drop(cache);
        assert_eq!(connect("udp:[2001:db8::1]:443").observed_domain, None);
    }

    #[test]
    fn startup_failure_is_redacted_and_kept_without_recording_logs() {
        let activity = Activity::default();
        let secret = "f0594cf1-14b5-4dcc-8123-4df23c516f10";
        let password = "test-reality-password";
        let secrets = [secret, password];
        activity.new_session();
        let output = format!("Xray fixture\nFailed to start: rejected ({secret}, {password})");
        read_output(output.as_bytes(), &activity, &secrets).unwrap();
        assert_eq!(
            activity.finish_startup().as_deref(),
            Some("Failed to start: rejected ([redacted], [redacted])"),
        );
        assert!(activity.logs().is_empty());

        activity.new_session();
        let prefix = "Failed to start: ";
        let padding = "x".repeat(LINE_LIMIT - prefix.len() - 8);
        let output = format!("{prefix}{padding}{secret}");
        read_output(output.as_bytes(), &activity, &secrets).unwrap();
        assert_eq!(
            activity.finish_startup().unwrap(),
            format!("{prefix}{padding}")
        );

        activity.new_session();
        read_output("Xray fixture\n".as_bytes(), &activity, &secrets).unwrap();
        assert!(activity.finish_startup().is_none());
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
            dns_servers: &["tcp://192.0.2.53:8853".into()],
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
