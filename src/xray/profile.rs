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

mod json;
mod ports;

const MAX_PROFILES: usize = 128;
const MAX_IMPORT: usize = 1024 * 1024;
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
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub custom_port: Option<u16>,
}

impl Profile {
    pub fn same_outbound(&self, other: &Self) -> bool {
        self.protected == other.protected
    }

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
    #[serde(default)]
    default_port: u16,
    #[serde(default)]
    active_profile_removed: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    manual_default_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    grandfathered_port: Option<u16>,
    #[serde(rename = "socks_port", skip_serializing)]
    legacy_port: Option<u16>,
    #[serde(rename = "active", skip_serializing)]
    legacy_active: Option<String>,
    pub profiles: Vec<Profile>,
    subscriptions: Vec<Subscription>,
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
            manual_default_port: 2081,
            grandfathered_port: None,
            legacy_port: None,
            legacy_active: None,
            profiles: Vec::new(),
            subscriptions: Vec::new(),
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
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(Self {
                    manual_default_port: ports::next_port(&BTreeSet::new())?,
                    ..Self::default()
                });
            }
            Err(error) => return Err(error.into()),
        };
        let mut bytes = Vec::new();
        file.take(MAX_SETTINGS + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_SETTINGS,
            "Xray settings exceed 2 MiB"
        );
        let mut settings: Self = serde_json::from_slice(&bytes).context("Invalid Xray settings")?;
        if let Some(port) = settings.legacy_port.take() {
            settings.migrate_ports(port)?;
            settings.save(path)?;
            return Ok(settings);
        }
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
        self.validate_ports()?;
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
        self.enabled_profiles()
            .next()
            .context("Turn on a VLESS profile first")
    }

    pub fn import_with_assets(&mut self, input: &str, root: &Path) -> Result<BTreeSet<String>> {
        self.import_source(&super::hpwnr::resolve(root, input)?, Some(root))
    }

    pub fn import(&mut self, input: &str) -> Result<BTreeSet<String>> {
        self.import_source(input, None)
    }

    fn import_source(&mut self, input: &str, root: Option<&Path>) -> Result<BTreeSet<String>> {
        let input = input.trim();
        ensure!(input.len() <= MAX_IMPORT, "Xray import exceeds 1 MiB");
        let input = unwrap_v2raytun(input)?;
        if link_scheme(&input).eq_ignore_ascii_case("https") {
            let url = https_url(&input)?;
            let existing = self.subscriptions.iter().find(|entry| {
                crate::platform::unprotect(&entry.protected_url)
                    .is_ok_and(|value| value == url.as_str())
            });
            if let Some(existing) = existing {
                return self.refresh_source(&existing.id.clone(), root);
            }
            ensure!(
                self.subscriptions.len() < MAX_PROFILES,
                "Too many subscriptions"
            );
            let nodes = fetch_subscription(&url, root)?;
            ensure!(!nodes.is_empty(), "The subscription contains no profiles");
            let id = new_id();
            let protected_url = crate::platform::windows::protect_secret(url.as_str())?;
            let default_port = ports::next_port(&self.reserved_ports())?;
            let domains = self.merge_nodes(nodes, Some(&id))?;
            self.subscriptions.push(Subscription {
                id,
                protected_url,
                default_port,
                active_profile_removed: false,
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
        self.refresh_source(id, None)
    }

    pub fn refresh_subscription_with_assets(
        &mut self,
        id: &str,
        root: &Path,
    ) -> Result<BTreeSet<String>> {
        self.refresh_source(id, Some(root))
    }

    fn refresh_source(&mut self, id: &str, root: Option<&Path>) -> Result<BTreeSet<String>> {
        let subscription = self
            .subscriptions
            .iter()
            .find(|source| source.id == id)
            .context("Subscription not found")?;
        let url = crate::platform::unprotect(&subscription.protected_url)
            .context("Could not open the subscription URL")?;
        let nodes = fetch_subscription(&https_url(&url)?, root)?;
        self.merge_nodes(nodes, Some(id))
    }

    fn merge_nodes(
        &mut self,
        nodes: Vec<Node>,
        subscription: Option<&str>,
    ) -> Result<BTreeSet<String>> {
        let select_first = self.profiles.is_empty() && self.subscriptions.is_empty();
        let domains = nodes
            .iter()
            .filter(|node| node.host.parse::<IpAddr>().is_err())
            .map(|node| node.host.clone())
            .collect();
        let endpoint = |host: &str, port, outbound: &Value| {
            (
                host.to_ascii_lowercase(),
                port,
                outbound["settings"]["id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_ascii_lowercase(),
            )
        };
        let mut existing = BTreeMap::new();
        let mut by_endpoint = BTreeMap::new();
        for profile in self
            .profiles
            .iter()
            .filter(|profile| profile.subscription.as_deref() == subscription)
        {
            let outbound = profile.outbound()?;
            let key = endpoint(&profile.host, profile.port, &outbound);
            by_endpoint
                .entry(key)
                .and_modify(|unique| *unique = None)
                .or_insert(Some(profile));
            existing.insert(serde_json::to_string(&outbound)?, profile);
        }
        let mut seen = HashSet::new();
        let mut candidates = Vec::new();
        let mut incoming = BTreeMap::new();
        for node in nodes {
            let serialized = serde_json::to_string(&node.outbound)?;
            if seen.insert(serialized.clone()) {
                let key = endpoint(&node.host, node.port, &node.outbound);
                *incoming.entry(key.clone()).or_insert(0usize) += 1;
                candidates.push((node, serialized, key));
            }
        }
        let mut replaced = Vec::new();
        for (node, serialized, key) in candidates {
            let exact = existing.get(&serialized).copied();
            if subscription.is_none() && exact.is_some() {
                continue;
            }
            let same = exact.or_else(|| {
                if subscription.is_some() && incoming.get(&key) == Some(&1) {
                    by_endpoint.get(&key).copied().flatten()
                } else {
                    None
                }
            });
            replaced.push(Profile {
                id: same.map_or_else(new_id, |profile| profile.id.clone()),
                name: node.name,
                host: node.host,
                port: node.port,
                protected: match exact {
                    Some(profile) => profile.protected.clone(),
                    None => crate::platform::windows::protect_secret(&serialized)?,
                },
                subscription: subscription.map(str::to_owned),
                enabled: same.is_some_and(|profile| profile.enabled),
                custom_port: same.and_then(|profile| profile.custom_port),
            });
        }
        let retained = self
            .profiles
            .iter()
            .filter(|profile| {
                subscription.is_none() || profile.subscription.as_deref() != subscription
            })
            .count();
        ensure!(
            retained + replaced.len() <= MAX_PROFILES,
            "Xray supports up to 128 profiles"
        );
        if let Some(id) = subscription {
            if let Some(source) = self.subscriptions.iter_mut().find(|source| source.id == id) {
                source.active_profile_removed |= self.profiles.iter().any(|profile| {
                    profile.subscription.as_deref() == Some(id)
                        && profile.enabled
                        && !replaced.iter().any(|next| next.id == profile.id)
                });
            }
            self.profiles
                .retain(|profile| profile.subscription.as_deref() != Some(id));
        }
        if select_first && let Some(first) = replaced.first_mut() {
            first.enabled = true;
        }
        self.profiles.extend(replaced);
        self.prune_hosts();
        Ok(domains)
    }

    pub fn remove_profile(&mut self, id: &str) {
        let Some(index) = self.profiles.iter().position(|profile| profile.id == id) else {
            return;
        };
        if let Some(id) = self.profiles.remove(index).subscription
            && !self
                .profiles
                .iter()
                .any(|profile| profile.subscription.as_deref() == Some(&id))
        {
            self.subscriptions.retain(|source| source.id != id);
        }
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
        let active_domains: Vec<_> = self
            .enabled_profiles()
            .filter_map(|profile| domains.take(profile.host.as_str()))
            .collect();
        let mut domains = active_domains.into_iter().chain(domains);
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

fn fetch_subscription(url: &Url, root: Option<&Path>) -> Result<Vec<Node>> {
    fetch_subscription_using(url, root, assets::get_subscription_with_hwid)
}

fn fetch_subscription_using(
    url: &Url,
    root: Option<&Path>,
    fetch: impl FnOnce(&str, Option<&str>) -> Result<Vec<u8>>,
) -> Result<Vec<Node>> {
    let hwid = if super::shadownet::matches(url) {
        Some(super::shadownet::device_id(root.context(
            "ShadowNet import requires the local module directory",
        )?)?)
    } else {
        None
    };
    let bytes = fetch(url.as_str(), hwid.as_deref())?;
    let nodes = parse_nodes_inner(&bytes, true)?;
    if hwid.is_some() {
        ensure!(
            !nodes.iter().any(|node| {
                let name = node.name.to_lowercase();
                name.contains("устройство не определено")
                    || name.contains("проверьте hwid")
                    || name.contains("device not detected")
                    || name.contains("check hwid")
            }),
            "ShadowNet did not accept this device. Check the device list and available device slots in your provider account."
        );
    }
    Ok(nodes)
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
    parse_nodes_inner(bytes, false)
}

fn parse_nodes_inner(bytes: &[u8], subscription: bool) -> Result<Vec<Node>> {
    ensure!(bytes.len() <= MAX_IMPORT, "Xray subscription exceeds 1 MiB");
    let text = std::str::from_utf8(bytes)
        .context("The subscription must be UTF-8")?
        .trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    let decoded;
    let text = if text.starts_with(['{', '[']) || text.contains("://") {
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
    if text.trim_start().starts_with(['{', '[']) {
        if subscription
            && text
                .bytes()
                .filter(|byte| !byte.is_ascii_whitespace())
                .eq(*b"[]")
        {
            return Ok(Vec::new());
        }
        return json::parse_nodes(text);
    }
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
    fn shadownet_downloads_reuse_one_saved_identity_and_other_sources_do_not_send_it() {
        let root = std::env::temp_dir().join(format!("true-proxy-subscription-{}", new_id()));
        let url = https_url("https://sub.shadow-net.site/example").unwrap();
        let mut saved = String::new();
        for _ in 0..2 {
            let nodes = fetch_subscription_using(&url, Some(&root), |source, hwid| {
                assert_eq!(source, url.as_str());
                let hwid = hwid.expect("ShadowNet requires HWID");
                if saved.is_empty() {
                    saved = hwid.to_owned();
                } else {
                    assert_eq!(hwid, saved);
                }
                Ok(NODE.as_bytes().to_vec())
            })
            .unwrap();
            assert_eq!(nodes.len(), 1);
        }
        let placeholder = NODE.replace("#Demo", "#Check%20HWID");
        let error = fetch_subscription_using(&url, Some(&root), |_, _| {
            Ok(placeholder.as_bytes().to_vec())
        })
        .err()
        .unwrap();
        assert!(error.to_string().contains("did not accept this device"));
        let other = https_url("https://example.test/list").unwrap();
        fetch_subscription_using(&other, None, |_, hwid| {
            assert!(hwid.is_none());
            Ok(NODE.as_bytes().to_vec())
        })
        .unwrap();
        fs::remove_file(root.join("subscription-device.dpapi")).unwrap();
        fs::remove_dir(root).unwrap();
    }

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
        assert_eq!(restored.default_port(None), 2081);
        assert_eq!(
            restored.selected().unwrap().outbound().unwrap()["settings"]["address"],
            "vpn.example.test"
        );
        assert_eq!(
            restored.selected().unwrap().id,
            settings.selected().unwrap().id
        );
    }

    fn add_source(settings: &mut Settings, id: &str, default_port: u16, body: &str) {
        settings
            .merge_nodes(parse_nodes(body.as_bytes()).unwrap(), Some(id))
            .unwrap();
        settings.subscriptions.push(Subscription {
            id: id.to_owned(),
            protected_url: String::new(),
            default_port,
            active_profile_removed: false,
        });
    }

    #[test]
    fn two_groups_inherit_ports_and_switch_only_the_conflicting_profile() {
        let mut settings = Settings::default();
        let second_node = NODE
            .replace("vpn.example.test", "us.example.test")
            .replace("#Demo", "#USA");
        add_source(&mut settings, "A", 2100, &format!("{NODE}\n{second_node}"));
        add_source(&mut settings, "B", 2200, NODE);
        let first = settings.profiles[0].id.clone();
        let second = settings.profiles[1].id.clone();
        let third = settings.profiles[2].id.clone();
        assert_eq!(settings.toggle_profile(&third).unwrap(), None);
        assert_eq!(
            settings.toggle_profile(&second).unwrap().as_deref(),
            Some("Demo")
        );
        assert!(settings.profiles[2].enabled);
        settings.set_custom_port(&first, Some(2201)).unwrap();
        assert_eq!(settings.toggle_profile(&first).unwrap(), None);
        assert_eq!(settings.enabled_profiles().count(), 3);
        assert!(settings.set_custom_port(&first, None).is_err());
        assert!(settings.set_custom_port(&first, Some(2200)).is_err());
        assert!(settings.set_custom_port(&first, Some(1023)).is_err());
        assert!(settings.set_default_port(Some("B"), 2100).is_err());
        assert!(settings.set_default_port(Some("B"), 2201).is_err());
        assert_eq!(settings.effective_port(&settings.profiles[0]), 2201);
        settings.set_default_port(Some("A"), 65535).unwrap();
        assert_eq!(settings.effective_port(&settings.profiles[1]), 65535);
        assert_eq!(settings.effective_port(&settings.profiles[2]), 2200);
    }

    #[test]
    fn refresh_preserves_identity_through_rename_and_tls_change_but_does_not_replace_removed_node()
    {
        let mut settings = Settings::default();
        add_source(&mut settings, "A", 2100, NODE);
        let original = settings.profiles[0].clone();
        settings.set_custom_port(&original.id, Some(2300)).unwrap();
        let renamed = NODE.replace("#Demo", "#Riga");
        settings
            .merge_nodes(parse_nodes(renamed.as_bytes()).unwrap(), Some("A"))
            .unwrap();
        assert!(settings.profiles[0].same_outbound(&original));
        let rotated = renamed.replace("fp=chrome", "fp=firefox");
        settings
            .merge_nodes(parse_nodes(rotated.as_bytes()).unwrap(), Some("A"))
            .unwrap();
        let profile = &settings.profiles[0];
        assert!(profile.enabled && !profile.same_outbound(&original));
        assert_eq!(profile.id, original.id);
        assert_eq!(profile.custom_port, Some(2300));
        let other = rotated.replace("vpn.example.test", "other.example.test");
        settings
            .merge_nodes(parse_nodes(other.as_bytes()).unwrap(), Some("A"))
            .unwrap();
        assert_eq!(settings.enabled_profiles().count(), 0);
        assert!(settings.active_profile_removed(Some("A")));
        assert_ne!(settings.profiles[0].id, original.id);
        assert_eq!(settings.profiles[0].custom_port, None);
        for body in ["[ ]", "W10="] {
            let nodes = parse_nodes_inner(body.as_bytes(), true).unwrap();
            settings.merge_nodes(nodes, Some("A")).unwrap();
            assert!(settings.profiles.is_empty());
            assert!(settings.active_profile_removed(Some("A")));
        }
    }

    #[test]
    fn migration_atomically_preserves_legacy_listener_in_its_source_or_first_container() {
        for active in [true, false] {
            let directory = std::env::temp_dir().join(format!("true-proxy-migrate-{}", new_id()));
            fs::create_dir_all(&directory).unwrap();
            let path = directory.join("settings.json");
            let mut fixture = Settings::default();
            add_source(&mut fixture, "A", 2100, NODE);
            add_source(&mut fixture, "B", 2200, NODE);
            let old = json!({
                "socks_port": 2082, "enabled": true,
                "active": active.then(|| fixture.profiles[1].id.clone()),
                "profiles": fixture.profiles.iter().map(|profile| json!({
                    "id": profile.id, "name": profile.name, "host": profile.host,
                    "port": profile.port, "protected": profile.protected, "subscription": profile.subscription
                })).collect::<Vec<_>>(),
                "subscriptions": [{"id":"A","protected_url":""},{"id":"B","protected_url":""}]
            });
            fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
            let migrated = Settings::load(&path).unwrap();
            assert_eq!(
                migrated.default_port(Some(if active { "B" } else { "A" })),
                2082
            );
            assert_eq!(migrated.enabled_profiles().count(), usize::from(active));
            assert!(migrated.enabled);
            assert_eq!(migrated.reserved_ports().len(), 3);
            let saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert!(saved.get("socks_port").is_none() && saved.get("active").is_none());
            assert_eq!(
                Settings::load(&path).unwrap().reserved_ports(),
                migrated.reserved_ports()
            );
            fs::remove_file(path).unwrap();
            fs::remove_dir(directory).unwrap();
        }
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
