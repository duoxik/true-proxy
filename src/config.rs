use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proxy {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: String,
    /// Only OS-protected ciphertext is persisted. Never log credentials.
    #[serde(default)]
    pub protected_password: Option<String>,
}

impl Proxy {
    pub fn password(&self) -> Result<Option<String>> {
        self.protected_password
            .as_deref()
            .map(crate::platform::unprotect)
            .transpose()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "proxy_id", rename_all = "snake_case")]
pub enum Action {
    #[default]
    Direct,
    Block,
    Proxy(String),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    #[default]
    Both,
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsPolicy {
    #[default]
    Inherit,
    Proxy,
    Direct,
    Block,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        let (start, end) = input.split_once('-').unwrap_or((input, input));
        let start = start.trim().parse().context("Некорректный порт")?;
        let end = end.trim().parse().context("Некорректная граница портов")?;
        ensure!(
            start > 0 && start <= end,
            "Диапазон портов должен быть в пределах 1–65535"
        );
        Ok(Self { start, end })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    #[serde(default)]
    pub process_names: Vec<String>,
    #[serde(default)]
    pub process_paths: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub domain_suffixes: Vec<String>,
    #[serde(default)]
    pub networks: Vec<IpNet>,
    #[serde(default)]
    pub ports: Vec<PortRange>,
    #[serde(default)]
    pub protocol: Protocol,
    pub action: Action,
    #[serde(default, skip_serializing)]
    pub dns: DnsPolicy,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsSettings {
    pub enabled: bool,
    pub proxy_id: Option<String>,
    pub resolver: IpAddr,
}
impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy_id: None,
            resolver: "1.1.1.1".parse().unwrap(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    #[serde(default = "initial_routing_state", alias = "start_enabled")]
    pub routing_enabled: bool,
    pub proxies: Vec<Proxy>,
    pub rules: Vec<Rule>,
    pub default_action: Action,
    // Read legacy profiles without retaining obsolete DNS proxy controls on save.
    #[serde(default, skip_serializing)]
    pub dns: DnsSettings,
}

fn initial_routing_state() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 2,
            routing_enabled: true,
            proxies: vec![],
            rules: vec![],
            default_action: Action::Direct,
            dns: DnsSettings::default(),
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 2,
            "Неизвестная версия настроек: {}",
            self.version
        );
        ensure!(
            self.proxies.len() <= 64 && self.rules.len() <= 1024,
            "Слишком много прокси или правил"
        );
        let mut ids = HashSet::new();
        for proxy in &self.proxies {
            ensure!(
                !proxy.id.is_empty() && ids.insert(&proxy.id),
                "Повторяющийся ID прокси"
            );
            ensure!(!proxy.name.trim().is_empty(), "Укажите название прокси");
            ensure!(
                !proxy.host.trim().is_empty() && !proxy.host.contains(['/', '\\', ':', ' '])
                    || proxy.host.parse::<IpAddr>().is_ok(),
                "Укажите адрес без протокола и порта"
            );
            ensure!(proxy.port != 0, "Порт должен быть в пределах 1–65535");
            ensure!(proxy.username.len() <= 255, "Логин SOCKS5 длиннее 255 байт");
        }
        let validate_action = |action: &Action| -> Result<()> {
            if let Action::Proxy(id) = action {
                ensure!(
                    ids.contains(id),
                    "Правило ссылается на отсутствующий прокси"
                );
            }
            Ok(())
        };
        validate_action(&self.default_action)?;
        let mut rule_ids = HashSet::new();
        for rule in &self.rules {
            ensure!(
                !rule.id.is_empty() && rule_ids.insert(&rule.id),
                "Повторяющийся ID правила"
            );
            ensure!(!rule.name.trim().is_empty(), "Укажите название правила");
            validate_action(&rule.action)?;
            for name in &rule.process_names {
                ensure!(
                    !name.is_empty() && !name.contains(['/', '\\', '*', '?']),
                    "Имя процесса должно быть точным именем файла"
                );
            }
            for path in &rule.process_paths {
                ensure!(
                    Path::new(path).is_absolute(),
                    "Путь процесса должен быть абсолютным"
                );
            }
            for domain in rule.domains.iter().chain(&rule.domain_suffixes) {
                ensure!(
                    !domain.is_empty()
                        && domain.len() <= 253
                        && domain.split('.').all(|label| !label.is_empty()
                            && label.len() <= 63
                            && label
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'-')),
                    "Некорректный домен: {domain}. Используйте ASCII / punycode"
                );
            }
            for port in &rule.ports {
                ensure!(
                    port.start > 0 && port.start <= port.end,
                    "Некорректный диапазон портов"
                );
            }
        }
        Ok(())
    }

    pub fn proxy(&self, id: &str) -> Result<&Proxy> {
        self.proxies
            .iter()
            .find(|p| p.id == id)
            .context("Прокси не найден")
    }

    pub fn remove_proxy(&mut self, id: &str) -> Result<()> {
        let used = |a: &Action| matches!(a, Action::Proxy(p) if p == id);
        if self.rules.iter().any(|r| used(&r.action)) || used(&self.default_action) {
            bail!(
                "Прокси используется в правилах или маршруте по умолчанию. Сначала измените эти настройки."
            );
        }
        self.proxies.retain(|p| p.id != id);
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let metadata = fs::metadata(path)?;
        ensure!(
            metadata.len() <= 2 * 1024 * 1024,
            "Файл настроек слишком большой"
        );
        let original = fs::read(path)?;
        let mut config: Self = serde_json::from_slice(&original)
            .context("Не удалось прочитать настройки. Исходный файл сохранен.")?;
        let upgrade = config.version == 1;
        if upgrade {
            // One-time user-requested expansion. New version-2 exact domains stay exact.
            for rule in &mut config.rules {
                for domain in std::mem::take(&mut rule.domains) {
                    if !rule
                        .domain_suffixes
                        .iter()
                        .any(|old| old.eq_ignore_ascii_case(&domain))
                    {
                        rule.domain_suffixes.push(domain);
                    }
                }
            }
            config.version = 2;
        }
        config.dns = DnsSettings::default();
        for rule in &mut config.rules {
            rule.dns = DnsPolicy::Inherit;
        }
        config.validate()?;
        if upgrade {
            backup_profile(path, &original)?;
            config.save(path)?;
        }
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(self)?;
        ensure!(
            bytes.len() <= 2 * 1024 * 1024,
            "Файл настроек превышает допустимые 2 МиБ"
        );
        use std::io::Write;
        let mut file = fs::File::create(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        crate::platform::replace_file(&temporary, path)
            .context("Не удалось атомарно сохранить настройки")
    }

    pub fn path() -> Result<PathBuf> {
        let root = std::env::var_os(if cfg!(windows) {
            "LOCALAPPDATA"
        } else {
            "HOME"
        })
        .context("Не найдена пользовательская папка")?;
        Ok(PathBuf::from(root)
            .join(if cfg!(windows) {
                "TrueProxy"
            } else {
                ".config/true-proxy"
            })
            .join("config.json"))
    }
}

fn backup_profile(path: &Path, original: &[u8]) -> Result<()> {
    use std::io::Write;
    for number in 0..100 {
        let backup = path.with_extension(format!("v1-backup-{number}.json"));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(backup)
        {
            Ok(mut file) => {
                file.write_all(original)?;
                file.sync_all()?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .context("Не удалось сохранить исходный профиль перед обновлением");
            }
        }
    }
    bail!("Не удалось создать резервную копию профиля: слишком много копий")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_is_valid_and_has_no_fake_servers() {
        let c = Config::default();
        c.validate().unwrap();
        assert!(c.proxies.is_empty());
    }
    #[test]
    fn validates_ports() {
        assert_eq!(
            PortRange::parse("443").unwrap(),
            PortRange {
                start: 443,
                end: 443
            }
        );
        assert!(PortRange::parse("80-90").is_ok());
        for s in ["0", "90-80", "65536", "abc", "1-2-3"] {
            assert!(PortRange::parse(s).is_err(), "{s}");
        }
    }
    #[test]
    fn rejects_unknown_configuration() {
        assert!(serde_json::from_str::<Config>(r#"{"version":99}"#).is_err());
    }
    #[test]
    fn cannot_delete_referenced_proxy() {
        let mut c = Config::default();
        c.proxies.push(Proxy {
            id: "p".into(),
            name: "VPN".into(),
            host: "127.0.0.1".into(),
            port: 1080,
            username: String::new(),
            protected_password: None,
        });
        c.default_action = Action::Proxy("p".into());
        assert!(c.remove_proxy("p").is_err());
        c.default_action = Action::Direct;
        c.remove_proxy("p").unwrap();
        assert!(c.proxies.is_empty());
    }
    #[test]
    fn legacy_dns_options_are_ignored_and_omitted_on_save() {
        let mut c = Config::default();
        c.dns.enabled = true;
        c.dns.proxy_id = Some("deleted-legacy-proxy".into());
        c.validate().unwrap();
        let json = serde_json::to_value(&c).unwrap();
        assert!(json.get("dns").is_none());
        assert!(!serde_json::from_value::<Config>(json).unwrap().dns.enabled);
    }

    #[test]
    fn old_profile_domains_expand_once_with_backup_and_new_exact_names_stay_exact() {
        let dir = std::env::temp_dir().join(format!("true-proxy-profile-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        let mut json = serde_json::to_value(Config::default()).unwrap();
        json["version"] = 1.into();
        json.as_object_mut().unwrap().remove("routing_enabled");
        json["start_enabled"] = false.into();
        json["rules"] = serde_json::json!([{
            "id": "game", "name": "Game", "enabled": true,
            "domains": ["steamserver.net", "deadorbit.net", "gravityshavings.net"],
            "domain_suffixes": ["steamserver.net"],
            "action": {"kind": "direct"}
        }]);
        let original = serde_json::to_vec(&json).unwrap();
        fs::write(&path, &original).unwrap();
        let mut config = Config::load(&path).unwrap();
        assert_eq!(config.version, 2);
        assert!(!config.routing_enabled);
        assert!(config.rules[0].domains.is_empty());
        assert_eq!(
            config.rules[0].domain_suffixes,
            ["steamserver.net", "deadorbit.net", "gravityshavings.net"]
        );
        let backup = path.with_extension("v1-backup-0.json");
        assert_eq!(fs::read(&backup).unwrap(), original);
        config.rules[0].domains = vec!["exact.example.com".into()];
        config.save(&path).unwrap();
        let reloaded = Config::load(&path).unwrap();
        assert_eq!(reloaded.rules[0].domains, ["exact.example.com"]);
        assert!(!reloaded.routing_enabled);
        let persisted = fs::read_to_string(&path).unwrap();
        assert!(!persisted.contains("start_enabled"));
        assert!(!path.with_extension("v1-backup-1.json").exists());
        fs::remove_file(path).unwrap();
        fs::remove_file(backup).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}
