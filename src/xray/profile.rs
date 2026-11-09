use super::assets;
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::{self, File},
    io::{ErrorKind, Read, Write},
    net::{IpAddr, ToSocketAddrs},
    path::Path,
    sync::OnceLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;

const MAX_PROFILES: usize = 128;
const MAX_SETTINGS: u64 = 2 * 1024 * 1024;
const HOST_LOOKUP_CONCURRENCY: usize = 4;
const HOST_LOOKUP_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    protected: String,
    pub subscription: Option<String>,
}

impl Profile {
    pub fn outbound(&self) -> Result<Value> {
        let text = crate::platform::unprotect(&self.protected)
            .context("Could not open the saved VLESS profile")?;
        serde_json::from_str(&text).context("Invalid saved VLESS profile")
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Subscription {
    id: String,
    protected_url: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub socks_port: u16,
    pub profiles: Vec<Profile>,
    subscriptions: Vec<Subscription>,
    pub active: Option<String>,
    pub dns: Vec<String>,
    pub hosts: BTreeMap<String, IpAddr>,
    pub direct_ips: Vec<String>,
    pub direct_domains: Vec<String>,
    pub geoip_url: String,
    pub geosite_url: String,
    pub geo_refresh_hours: u16,
    pub geo_refreshed_at: u64,
    pub log_recording: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            socks_port: 2081,
            profiles: Vec::new(),
            subscriptions: Vec::new(),
            active: None,
            dns: Vec::new(),
            hosts: BTreeMap::new(),
            direct_ips: vec!["geoip:ru".into()],
            direct_domains: vec!["geosite:category-ru".into()],
            geoip_url: assets::DEFAULT_GEOIP_URL.into(),
            geosite_url: assets::DEFAULT_GEOSITE_URL.into(),
            geo_refresh_hours: 24,
            geo_refreshed_at: 0,
            log_recording: false,
        }
    }
}

impl Settings {
    pub fn load(path: &Path) -> Result<Self> {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error.into()),
        };
        let mut bytes = Vec::new();
        file.take(MAX_SETTINGS + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_SETTINGS,
            "Xray settings exceed 2 MiB"
        );
        let settings: Self = serde_json::from_slice(&bytes).context("Invalid Xray settings")?;
        settings.validate()?;
        Ok(settings)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let contents = serde_json::to_vec_pretty(self)?;
        ensure!(
            contents.len() as u64 <= MAX_SETTINGS,
            "Xray settings exceed 2 MiB"
        );
        fs::create_dir_all(path.parent().context("Missing Xray settings directory")?)?;
        let temporary = path.with_extension("tmp");
        let mut file = File::create(&temporary)?;
        file.write_all(&contents)?;
        file.sync_all()?;
        drop(file);
        crate::platform::replace_file(&temporary, path).context("Could not save Xray settings")
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.socks_port != 0,
            "The SOCKS port must be between 1 and 65535"
        );
        ensure!(
            self.profiles.len() <= MAX_PROFILES,
            "Too many Xray profiles"
        );
        ensure!(
            self.subscriptions.len() <= MAX_PROFILES && self.hosts.len() <= MAX_PROFILES,
            "Too many Xray settings entries"
        );
        let ids: HashSet<_> = self
            .profiles
            .iter()
            .map(|profile| profile.id.as_str())
            .collect();
        let sources: HashSet<_> = self
            .subscriptions
            .iter()
            .map(|source| source.id.as_str())
            .collect();
        ensure!(
            ids.len() == self.profiles.len() && sources.len() == self.subscriptions.len(),
            "Duplicate Xray profile IDs"
        );
        ensure!(
            self.active.as_deref().is_none_or(|id| ids.contains(id)),
            "The active Xray profile is missing"
        );
        for profile in &self.profiles {
            ensure!(
                !profile.id.is_empty()
                    && profile.port != 0
                    && profile.host.len() <= 253
                    && !profile.name.is_empty()
                    && profile.name.chars().count() <= 80
                    && profile
                        .subscription
                        .as_deref()
                        .is_none_or(|id| sources.contains(id)),
                "Invalid Xray profile"
            );
        }
        ensure!(
            self.geo_refresh_hours <= 720,
            "Geo refresh must be between 0 and 720 hours"
        );
        https_url(&self.geoip_url)?;
        https_url(&self.geosite_url)?;
        parse_tags(&self.direct_ips.join(","), "geoip")?;
        parse_tags(&self.direct_domains.join(","), "geosite")?;
        parse_dns(&self.dns.join(","))?;
        Ok(())
    }

    pub fn selected(&self) -> Result<&Profile> {
        self.active
            .as_deref()
            .and_then(|id| self.profiles.iter().find(|profile| profile.id == id))
            .context("Select a VLESS profile first")
    }

    pub fn import_with_assets(&mut self, input: &str, root: &Path) -> Result<BTreeSet<String>> {
        self.import(&super::hpwnr::resolve(root, input)?)
    }

    pub fn import(&mut self, input: &str) -> Result<BTreeSet<String>> {
        let input = input.trim();
        ensure!(input.len() <= 256 * 1024, "Xray import exceeds 256 KiB");
        let input = unwrap_v2raytun(input)?;
        if link_scheme(&input).eq_ignore_ascii_case("https") {
            let url = https_url(&input)?;
            let existing = self.subscriptions.iter().find(|entry| {
                crate::platform::unprotect(&entry.protected_url)
                    .is_ok_and(|value| value == url.as_str())
            });
            if let Some(existing) = existing {
                return self.refresh_subscription(&existing.id.clone());
            }
            let nodes = fetch_subscription(&url)?;
            let id = new_id();
            let domains = self.merge_nodes(nodes, Some(&id))?;
            self.subscriptions.push(Subscription {
                id,
                protected_url: crate::platform::windows::protect_secret(url.as_str())?,
            });
            Ok(domains)
        } else {
            self.merge_nodes(parse_nodes(input.as_bytes())?, None)
        }
    }

    pub fn subscription_ids(&self) -> impl Iterator<Item = &str> {
        self.subscriptions.iter().map(|source| source.id.as_str())
    }

    pub fn refresh_subscription(&mut self, id: &str) -> Result<BTreeSet<String>> {
        let subscription = self
            .subscriptions
            .iter()
            .find(|source| source.id == id)
            .context("Subscription not found")?;
        let url = crate::platform::unprotect(&subscription.protected_url)
            .context("Could not open the subscription URL")?;
        let nodes = fetch_subscription(&https_url(&url)?)?;
        self.merge_nodes(nodes, Some(id))
    }

    fn merge_nodes(
        &mut self,
        nodes: Vec<Node>,
        subscription: Option<&str>,
    ) -> Result<BTreeSet<String>> {
        let select_first = self.profiles.is_empty() && self.active.is_none();
        let domains = nodes
            .iter()
            .filter(|node| node.host.parse::<IpAddr>().is_err())
            .map(|node| node.host.clone())
            .collect();
        let existing: BTreeMap<_, _> = self
            .profiles
            .iter()
            .filter(|profile| profile.subscription.as_deref() == subscription)
            .filter_map(|profile| {
                crate::platform::unprotect(&profile.protected)
                    .ok()
                    .map(|outbound| (outbound, profile))
            })
            .collect();
        let mut replaced = Vec::new();
        let mut seen = HashSet::new();
        for node in nodes {
            let serialized = serde_json::to_string(&node.outbound)?;
            if !seen.insert(serialized.clone()) {
                continue;
            }
            let same = existing.get(&serialized);
            if subscription.is_none() && same.is_some() {
                continue;
            }
            replaced.push(Profile {
                id: same.map_or_else(new_id, |profile| profile.id.clone()),
                name: node.name,
                host: node.host,
                port: node.port,
                protected: match same {
                    Some(profile) => profile.protected.clone(),
                    None => crate::platform::windows::protect_secret(&serialized)?,
                },
                subscription: subscription.map(str::to_owned),
            });
        }
        if let Some(subscription) = subscription {
            self.profiles.retain(|profile| {
                profile.subscription.as_deref() != Some(subscription)
                    || self.active.as_deref() == Some(&profile.id)
                        && !replaced.iter().any(|next| next.id == profile.id)
            });
        }
        ensure!(
            self.profiles.len() + replaced.len() <= MAX_PROFILES,
            "Xray supports up to 128 profiles"
        );
        self.profiles.extend(replaced);
        if select_first {
            self.active = self.profiles.first().map(|profile| profile.id.clone());
        }
        self.prune_hosts();
        Ok(domains)
    }

    pub fn remove_profile(&mut self, id: &str) {
        self.profiles.retain(|profile| profile.id != id);
        if self.active.as_deref() == Some(id) {
            self.active = None;
        }
        self.subscriptions.retain(|source| {
            self.profiles
                .iter()
                .any(|profile| profile.subscription.as_deref() == Some(&source.id))
        });
        self.prune_hosts();
    }

    pub fn host_domains(&self) -> BTreeSet<&str> {
        self.profiles
            .iter()
            .map(|profile| profile.host.as_str())
            .filter(|host| host.parse::<IpAddr>().is_err())
            .collect()
    }

    pub fn upstream_ip(&self, profile: &Profile) -> Option<IpAddr> {
        profile
            .host
            .parse()
            .ok()
            .or_else(|| self.hosts.get(&profile.host).copied())
    }

    pub fn prune_hosts(&mut self) {
        self.hosts.retain(|host, _| {
            host.parse::<IpAddr>().is_err()
                && self.profiles.iter().any(|profile| profile.host == *host)
        });
    }

    pub fn resolve_hosts(&mut self, mut domains: BTreeSet<String>) -> usize {
        if domains.is_empty() {
            return 0;
        }
        let count = domains.len();
        // Share the blocking thread limit even if Windows takes longer than our deadline.
        static RESOLVER: OnceLock<Option<tokio::runtime::Runtime>> = OnceLock::new();
        let Some(resolver) = RESOLVER.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .max_blocking_threads(HOST_LOOKUP_CONCURRENCY)
                .build()
                .ok()
        }) else {
            return count;
        };
        let active_domain = self
            .selected()
            .ok()
            .and_then(|profile| domains.take(profile.host.as_str()));
        let mut domains = active_domain.into_iter().chain(domains);
        let mut lookups = tokio::task::JoinSet::new();
        let mut resolved = 0;
        resolver.block_on(async {
            let _ = tokio::time::timeout(HOST_LOOKUP_TIMEOUT, async {
                loop {
                    while lookups.len() < HOST_LOOKUP_CONCURRENCY {
                        let Some(host) = domains.next() else { break };
                        let previous = self.hosts.get(&host).copied();
                        lookups.spawn_blocking(move || {
                            let mut addresses = (host.as_str(), 0).to_socket_addrs().ok()?;
                            let first = addresses.next()?.ip();
                            let address = previous
                                .filter(|ip| {
                                    *ip == first || addresses.any(|address| address.ip() == *ip)
                                })
                                .unwrap_or(first);
                            Some((host, address))
                        });
                    }
                    match lookups.join_next().await {
                        Some(Ok(Some((host, address)))) => {
                            self.hosts.insert(host, address);
                            resolved += 1;
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
            })
            .await;
        });
        count - resolved
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn new_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(1);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{stamp:x}-{:x}", SEQUENCE.fetch_add(1, Ordering::Relaxed))
}

pub fn https_url(input: &str) -> Result<Url> {
    ensure!(input.len() <= 8192, "The HTTPS URL is too long");
    let url = Url::parse(input.trim()).map_err(|_| anyhow::anyhow!("Enter a valid HTTPS URL"))?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "Enter an HTTPS URL without credentials or a fragment"
    );
    Ok(url)
}

pub fn parse_dns(text: &str) -> Result<Vec<String>> {
    if matches!(
        text.trim().to_ascii_lowercase().as_str(),
        "system" | "default"
    ) {
        return Ok(Vec::new());
    }
    let servers = split_list(text);
    validate_dns_servers(&servers)?;
    Ok(servers)
}

pub(super) fn validate_dns_servers(servers: &[String]) -> Result<()> {
    ensure!(servers.len() <= 8, "Enter at most eight DNS servers");
    for server in servers {
        if server.parse::<IpAddr>().is_ok() {
            continue;
        }
        ensure!(
            server.len() <= 1024 && !server.chars().any(char::is_whitespace),
            "Enter a DNS server address up to 1024 characters without whitespace"
        );
        if server.starts_with("tcp://") {
            let url = Url::parse(server).context("Enter a TCP DNS URL such as tcp://1.1.1.1:53")?;
            ensure!(
                url.host_str()
                    .is_some_and(|host| url::Host::parse(host).is_ok())
                    && !server.contains(['@', '%', '\\'])
                    && url.port() != Some(0)
                    && url.path().is_empty()
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "Enter a TCP DNS URL with a host and optional port, such as tcp://1.1.1.1:53"
            );
        } else {
            let url = https_url(server)
                .context("DNS servers must be IP addresses, TCP DNS URLs or HTTPS DoH URLs")?;
            ensure!(
                url.path() != "/" && url.port() != Some(0),
                "Enter a complete HTTPS DoH URL"
            );
        }
    }
    Ok(())
}

pub fn parse_tags(text: &str, kind: &str) -> Result<Vec<String>> {
    let tags = split_list(text);
    ensure!(tags.len() <= 32, "Enter at most 32 geo tags per field");
    tags.into_iter()
        .map(|tag| {
            let value = tag
                .strip_prefix(kind)
                .and_then(|value| value.strip_prefix(':'))
                .unwrap_or(&tag);
            ensure!(valid_geo_code(value, kind), "Invalid {kind} tag");
            Ok(format!("{kind}:{}", value.to_ascii_lowercase()))
        })
        .collect()
}

pub(super) fn valid_geo_code(code: &str, kind: &str) -> bool {
    !code.is_empty()
        && code.len() <= 80
        && !code.starts_with(['!', '@'])
        && code.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_')
                || matches!((kind, byte), ("geoip", b'@') | ("geosite", b'!'))
        })
}

fn split_list(text: &str) -> Vec<String> {
    text.split([',', '\n'])
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

fn fetch_subscription(url: &Url) -> Result<Vec<Node>> {
    let bytes = assets::get_subscription(url.as_str())
        .map_err(|_| anyhow::anyhow!("Could not download the subscription"))?;
    parse_nodes(&bytes)
}

fn link_scheme(input: &str) -> &str {
    input.split_once("://").map_or("", |(scheme, _)| scheme)
}

fn unwrap_v2raytun(input: &str) -> Result<Cow<'_, str>> {
    let Some((scheme, path)) = input.split_once("://") else {
        return Ok(Cow::Borrowed(input));
    };
    if !scheme.eq_ignore_ascii_case("v2raytun") {
        return Ok(Cow::Borrowed(input));
    }
    let (action, payload) = path.split_once('/').unwrap_or((path, ""));
    ensure!(
        !action.eq_ignore_ascii_case("crypt"),
        "Encrypted v2RayTun links require the original HTTPS subscription or VLESS link"
    );
    ensure!(
        action.eq_ignore_ascii_case("import") && !payload.is_empty(),
        "Expected a v2raytun://import/ link with a VLESS or HTTPS URL"
    );

    let supported = |value: &str| {
        let scheme = link_scheme(value);
        scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("vless")
    };
    // Decode only an encoded wrapper. Escapes in an already plain URL belong to that URL.
    let payload = if supported(payload) {
        Cow::Borrowed(payload)
    } else {
        percent_decode_str(payload)
            .decode_utf8()
            .context("Invalid encoding in the v2RayTun import link")?
    };
    ensure!(
        supported(&payload) && !payload.chars().any(char::is_control),
        "A v2RayTun import link must contain a single VLESS or HTTPS URL"
    );
    Ok(payload)
}

struct Node {
    name: String,
    host: String,
    port: u16,
    outbound: Value,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RealitySettings {
    server_name: String,
    fingerprint: String,
    pub(super) password: String,
    short_id: String,
    spider_x: String,
    pub(super) mldsa65_verify: String,
}

impl RealitySettings {
    pub(super) fn validate(&self) -> Result<()> {
        let key_length = |value: &str, size| {
            general_purpose::URL_SAFE_NO_PAD
                .decode(value)
                .is_ok_and(|bytes| bytes.len() == size)
        };
        ensure!(
            valid_server_name(&self.server_name),
            "Invalid REALITY server name"
        );
        ensure!(
            valid_fingerprint(&self.fingerprint)
                && !matches!(
                    self.fingerprint.to_ascii_lowercase().as_str(),
                    "unsafe" | "hellogolang"
                ),
            "Invalid REALITY fingerprint"
        );
        ensure!(
            key_length(&self.password, 32),
            "Invalid REALITY public key (pbk)"
        );
        ensure!(
            self.short_id.len() <= 16
                && self.short_id.len().is_multiple_of(2)
                && self.short_id.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "Invalid REALITY short ID (sid)"
        );
        let path = self.spider_x.as_bytes();
        ensure!(
            path.is_empty()
                || (path.starts_with(b"/")
                    && !path.starts_with(b"//")
                    && !self.spider_x.chars().any(char::is_control)
                    && path.iter().enumerate().all(|(i, &byte)| byte != b'%'
                        || path
                            .get(i + 1..i + 3)
                            .is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit)))),
            "Invalid REALITY spider path (spx)"
        );
        ensure!(
            self.mldsa65_verify.is_empty() || key_length(&self.mldsa65_verify, 1952),
            "Invalid REALITY verification key (pqv)"
        );
        Ok(())
    }
}

fn valid_server_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && !name.chars().any(|c| c.is_control() || c.is_whitespace())
}

fn valid_fingerprint(fingerprint: &str) -> bool {
    !fingerprint.is_empty()
        && fingerprint.len() <= 32
        && fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn parse_nodes(bytes: &[u8]) -> Result<Vec<Node>> {
    ensure!(
        bytes.len() <= 256 * 1024,
        "Xray subscription exceeds 256 KiB"
    );
    let text = std::str::from_utf8(bytes)
        .context("The subscription must be UTF-8")?
        .trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    let decoded;
    let text = if text.contains("://") {
        text
    } else {
        let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        decoded = [
            general_purpose::STANDARD,
            general_purpose::STANDARD_NO_PAD,
            general_purpose::URL_SAFE,
            general_purpose::URL_SAFE_NO_PAD,
        ]
        .into_iter()
        .find_map(|engine| engine.decode(&compact).ok())
        .context("Paste a vless:// link or a text/Base64 VLESS subscription")?;
        std::str::from_utf8(&decoded).context("The subscription must be UTF-8")?
    };
    if text.lines().count() == 1 {
        return parse_node(text.trim()).map(|node| vec![node]);
    }
    let mut nodes = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if let Ok(node) = parse_node(line) {
            nodes.push(node);
            ensure!(
                nodes.len() <= MAX_PROFILES,
                "Subscription contains more than 128 supported nodes"
            );
        }
    }
    ensure!(
        !nodes.is_empty(),
        "No supported VLESS RAW/TCP profiles with TLS or REALITY were found"
    );
    Ok(nodes)
}

fn parse_node(line: &str) -> Result<Node> {
    ensure!(line.len() <= 8192, "The VLESS link is too long");
    let url = Url::parse(line).map_err(|_| anyhow::anyhow!("Invalid VLESS link"))?;
    ensure!(
        url.scheme() == "vless" && url.password().is_none(),
        "Expected a vless:// link"
    );
    let host = url
        .host_str()
        .context("Missing VLESS server")?
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    let port = url
        .port()
        .filter(|port| *port != 0)
        .context("Missing VLESS server port")?;
    let id = url.username();
    ensure!(
        id.len() == 36
            && id.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            }),
        "The VLESS link must contain a valid UUID"
    );
    let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
    let field = |key, default| query.get(key).map_or(default, String::as_str);
    let security = field("security", "");
    ensure!(
        matches!(field("type", "tcp"), "tcp" | "raw")
            && matches!(security, "tls" | "reality")
            && field("headerType", "none") == "none"
            && field("encryption", "none") == "none",
        "Only VLESS RAW/TCP with TLS or REALITY is supported"
    );
    let flow = field("flow", "");
    ensure!(
        matches!(flow, "" | "xtls-rprx-vision" | "xtls-rprx-vision-udp443"),
        "Unsupported VLESS flow"
    );
    ensure!(
        !matches!(field("allowInsecure", ""), "1" | "true")
            && !matches!(field("insecure", ""), "1" | "true"),
        "TLS verification is required"
    );
    let sni = field("sni", &host);
    let stream = if security == "reality" {
        let reality = RealitySettings {
            server_name: sni.to_owned(),
            fingerprint: field("fp", "chrome").to_owned(),
            password: field("pbk", "").to_owned(),
            short_id: field("sid", "").to_owned(),
            spider_x: field("spx", "").to_owned(),
            mldsa65_verify: field("pqv", "").to_owned(),
        };
        reality.validate()?;
        json!({"network": "raw", "security": "reality", "realitySettings": reality})
    } else {
        ensure!(valid_server_name(sni), "Invalid TLS server name");
        let mut tls = json!({"serverName": sni});
        let fingerprint = field("fp", "");
        if !fingerprint.is_empty() {
            ensure!(valid_fingerprint(fingerprint), "Invalid TLS fingerprint");
            tls["fingerprint"] = json!(fingerprint);
        }
        let alpn = split_list(field("alpn", ""));
        if !alpn.is_empty() {
            ensure!(
                alpn.len() <= 8
                    && alpn
                        .iter()
                        .all(|value| value.len() <= 32 && !value.chars().any(char::is_control)),
                "Invalid TLS ALPN"
            );
            tls["alpn"] = json!(alpn);
        }
        json!({"network": "raw", "security": "tls", "tlsSettings": tls})
    };
    let name = url
        .fragment()
        .and_then(|fragment| {
            url::form_urlencoded::parse(fragment.as_bytes())
                .next()
                .map(|(name, _)| name.into_owned())
        })
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect::<String>();
    if host.is_empty() || host.len() > 253 {
        bail!("Invalid VLESS server address");
    }
    Ok(Node {
        name: if name.is_empty() { host.clone() } else { name },
        host: host.clone(),
        port,
        outbound: json!({
            "protocol": "vless",
            "settings": { "address": host, "port": port, "id": id.to_ascii_lowercase(), "encryption": "none", "flow": flow },
            "streamSettings": stream
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE: &str = "vless://00000000-0000-4000-8000-000000000001@vpn.example.test:443?type=tcp&security=tls&flow=xtls-rprx-vision&sni=cert.example.test&alpn=http%2F1.1&fp=chrome#Demo";

    #[test]
    fn imports_wrapped_vless_and_keeps_subscription_url_escapes() {
        let mut settings = Settings::default();
        settings
            .import(&format!("v2raytun://import/{NODE}"))
            .unwrap();
        let encoded =
            percent_encoding::utf8_percent_encode(NODE, percent_encoding::NON_ALPHANUMERIC);
        settings
            .import(&format!("V2RAYTUN://IMPORT/{encoded}"))
            .unwrap();
        assert_eq!(settings.profiles.len(), 1);
        assert_eq!(settings.selected().unwrap().name, "Demo");

        let url = "https://example.test/list?token=a+b%2Fc&option=1";
        let encoded =
            percent_encoding::utf8_percent_encode(url, percent_encoding::NON_ALPHANUMERIC);
        assert_eq!(
            unwrap_v2raytun(&format!("v2raytun://import/{url}")).unwrap(),
            url
        );
        assert_eq!(
            unwrap_v2raytun(&format!("v2raytun://import/{encoded}")).unwrap(),
            url
        );
    }

    #[test]
    fn rejects_encrypted_and_unsupported_v2raytun_links() {
        let mut settings = Settings::default();
        let error = settings.import("v2raytun://crypt/example").unwrap_err();
        assert!(error.to_string().contains("Encrypted v2RayTun links"));
        assert!(
            settings
                .import("v2raytun://import/http://example.test")
                .is_err()
        );
        assert!(
            settings
                .import("v2raytun://import/https%3A%2F%2Fexample.test%0Aother")
                .is_err()
        );
        assert!(settings.profiles.is_empty());
    }

    #[test]
    fn vless_and_base64_subscription_preserve_tls_and_filter_unsupported_nodes() {
        let nodes = parse_nodes(NODE.as_bytes()).unwrap();
        assert_eq!(nodes[0].outbound["settings"]["flow"], "xtls-rprx-vision");
        assert_eq!(
            nodes[0].outbound["streamSettings"]["tlsSettings"]["serverName"],
            "cert.example.test"
        );
        let subscription = general_purpose::STANDARD.encode(format!(
            "{NODE}\n{}",
            NODE.replace("security=tls", "security=reality")
        ));
        assert_eq!(parse_nodes(subscription.as_bytes()).unwrap().len(), 1);
        assert!(parse_nodes(NODE.replace("security=tls", "security=none").as_bytes()).is_err());
    }

    #[test]
    fn profile_secret_is_protected_and_selection_survives_round_trip() {
        let mut settings = Settings::default();
        settings.import(NODE).unwrap();
        let serialized = serde_json::to_string(&settings).unwrap();
        assert!(!serialized.contains("00000000-0000-4000-8000-000000000001"));
        let restored: Settings = serde_json::from_str(&serialized).unwrap();
        assert_eq!(restored.socks_port, 2081);
        assert_eq!(
            restored.selected().unwrap().outbound().unwrap()["settings"]["address"],
            "vpn.example.test"
        );
        assert_eq!(restored.active, settings.active);
    }

    #[test]
    fn host_cache_keeps_shared_domain_until_its_last_profile_is_removed() {
        let mut settings = Settings::default();
        let domains = settings.import(NODE).unwrap();
        assert_eq!(domains, BTreeSet::from(["vpn.example.test".to_owned()]));
        settings.import(&NODE.replace(":443?", ":8443?")).unwrap();
        settings
            .import(&NODE.replace("vpn.example.test", "192.0.2.10"))
            .unwrap();
        let address = "192.0.2.11".parse().unwrap();
        settings.hosts.insert("vpn.example.test".into(), address);

        let first = settings.profiles[0].id.clone();
        settings.remove_profile(&first);
        assert_eq!(settings.upstream_ip(&settings.profiles[0]), Some(address));
        assert_eq!(
            settings.upstream_ip(&settings.profiles[1]),
            Some("192.0.2.10".parse().unwrap())
        );

        let last = settings.profiles[0].id.clone();
        settings.remove_profile(&last);
        assert!(settings.hosts.is_empty());
    }

    #[test]
    fn failed_host_resolution_preserves_previously_saved_address() {
        let mut settings = Settings::default();
        let address = "192.0.2.11".parse().unwrap();
        // The system resolver rejects a name containing a NUL before querying DNS.
        let host = "invalid\0host".to_owned();
        settings.hosts.insert(host.clone(), address);

        assert_eq!(settings.resolve_hosts(BTreeSet::from([host.clone()])), 1);
        assert_eq!(settings.hosts.get(&host), Some(&address));
    }

    #[test]
    fn tunnel_dns_accepts_tcp_resolvers_with_optional_ports() {
        let resolvers = [
            "tcp://192.0.2.53:8853",
            "tcp://[2001:db8::53]:5353",
            "tcp://resolver.example",
            "https://resolver.example/dns-query",
            "192.0.2.54",
        ];
        assert_eq!(parse_dns(&resolvers.join(", ")).unwrap(), resolvers);
        for invalid in [
            "tcp://",
            "tcp://resolver.example:0",
            "tcp://resolver.example:65536",
            "tcp://resolver.example:8853/path",
            "tcp://resolver.example?key=value",
            "tcp://resolver.example#fragment",
            "tcp://user@resolver.example",
            "tcp://%65xample.test",
            "tcp+local://resolver.example",
        ] {
            assert!(parse_dns(invalid).is_err(), "{invalid}");
        }
    }
}
