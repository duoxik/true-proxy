//! Portable routing configuration. Runtime preferences and DPAPI ciphertext stay local.
use crate::config::{Action, Config, DnsPolicy, Proxy, Rule};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

pub const MAX_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u32,
    pub proxies: Vec<PortableProxy>,
    pub rules: Vec<Rule>,
    pub default_action: Action,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableProxy {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: Option<String>,
}

impl Profile {
    pub fn parse(text: &str) -> Result<Self> {
        ensure!(text.len() <= MAX_BYTES, "Конфигурация превышает 2 МиБ");
        let mut profile: Self = serde_json::from_str(text).map_err(|error| {
            anyhow::anyhow!(
                "JSON, строка {}, столбец {}: {}",
                error.line(),
                error.column(),
                error
            )
        })?;
        for rule in &mut profile.rules {
            rule.dns = DnsPolicy::Inherit;
        }
        profile.validate()?;
        Ok(profile)
    }
    pub fn export(config: &Config) -> Result<String> {
        config.validate()?;
        let proxies = config
            .proxies
            .iter()
            .map(|proxy| {
                Ok(PortableProxy {
                    id: proxy.id.clone(),
                    name: proxy.name.clone(),
                    host: proxy.host.clone(),
                    port: proxy.port,
                    username: proxy.username.clone(),
                    password: proxy.password().with_context(|| {
                        format!("Не удалось прочитать пароль прокси «{}»", proxy.name)
                    })?,
                })
            })
            .collect::<Result<_>>()?;
        Self {
            version: 2,
            proxies,
            rules: config.rules.clone(),
            default_action: config.default_action.clone(),
        }
        .pretty()
    }
    pub fn pretty(&self) -> Result<String> {
        let result = serde_json::to_string_pretty(self)?;
        ensure!(result.len() <= MAX_BYTES, "Конфигурация превышает 2 МиБ");
        Ok(result)
    }
    fn unprotected_proxy(proxy: &PortableProxy) -> Proxy {
        Proxy {
            id: proxy.id.clone(),
            name: proxy.name.clone(),
            host: proxy.host.clone(),
            port: proxy.port,
            username: proxy.username.clone(),
            protected_password: None,
        }
    }
    fn validate(&self) -> Result<()> {
        for (index, proxy) in self.proxies.iter().enumerate() {
            ensure!(
                proxy
                    .password
                    .as_ref()
                    .is_none_or(|password| password.len() <= 255),
                "proxies[{index}].password: пароль SOCKS5 длиннее 255 байт"
            );
        }
        Config {
            version: self.version,
            proxies: self.proxies.iter().map(Self::unprotected_proxy).collect(),
            rules: self.rules.clone(),
            default_action: self.default_action.clone(),
            ..Config::default()
        }
        .validate()
        .context("Некорректная конфигурация")
    }
    pub fn apply(self, config: &mut Config) -> Result<()> {
        self.validate()?;
        let proxies = self
            .proxies
            .iter()
            .map(|portable| {
                let mut proxy = Self::unprotected_proxy(portable);
                proxy.protected_password = if let Some(previous) =
                    config.proxies.iter().find(|p| p.id == portable.id)
                    && previous.password().ok().flatten() == portable.password
                {
                    previous.protected_password.clone()
                } else {
                    portable
                        .password
                        .as_deref()
                        .map(crate::platform::protect)
                        .transpose()
                        .with_context(|| {
                            format!("Не удалось защитить пароль прокси «{}»", portable.name)
                        })?
                };
                Ok(proxy)
            })
            .collect::<Result<_>>()?;
        config.proxies = proxies;
        config.rules = self.rules;
        config.default_action = self.default_action;
        // routing_enabled, update preferences and Windows startup are not imported.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn text() -> String {
        serde_json::json!({"version":2,"proxies":[{"id":"vpn","name":"VPN","host":"127.0.0.1","port":1080}],"rules":[],"default_action":{"kind":"proxy","proxy_id":"vpn"}}).to_string()
    }
    #[test]
    fn rejects_invalid_json_schema_references_and_duplicate_keys() {
        assert!(
            Profile::parse("{")
                .err()
                .unwrap()
                .to_string()
                .contains("строка")
        );
        for invalid in [
            text().replace("1080", "0"),
            text().replace("\"version\":2", "\"version\":99"),
            text().replace("\"rules\":[]", "\"rules\":[],\"extra\":true"),
            text().replace("\"rules\":[]", "\"rules\":[],\"rules\":[]"),
            text().replace("\"proxy_id\":\"vpn\"", "\"proxy_id\":\"missing\""),
        ] {
            assert!(Profile::parse(&invalid).is_err());
        }
        assert!(Profile::parse(&" ".repeat(MAX_BYTES + 1)).is_err());
    }
    #[test]
    fn import_preserves_pause_and_exports_only_network_configuration() {
        let mut config = Config {
            routing_enabled: false,
            ..Config::default()
        };
        Profile::parse(&text()).unwrap().apply(&mut config).unwrap();
        assert!(!config.routing_enabled);
        let exported = Profile::export(&config).unwrap();
        assert!(
            !exported.contains("routing_enabled")
                && !exported.contains("protected_password")
                && !exported.contains("\"dns\"")
        );
        assert!(Profile::parse(&exported).is_ok());
    }
    #[cfg(windows)]
    #[test]
    fn portable_password_roundtrip_is_plaintext_only_in_export_and_protected_at_rest() {
        let mut config = Config::default();
        let json = text().replace(
            "\"port\":1080",
            "\"port\":1080,\"password\":\"тестовый пароль\"",
        );
        Profile::parse(&json).unwrap().apply(&mut config).unwrap();
        let ciphertext = config.proxies[0].protected_password.clone();
        assert_eq!(
            config.proxies[0].password().unwrap().as_deref(),
            Some("тестовый пароль")
        );
        let disk = serde_json::to_string(&config).unwrap();
        assert!(!disk.contains("тестовый пароль"));
        let exported = Profile::export(&config).unwrap();
        assert!(exported.contains("тестовый пароль"));
        Profile::parse(&exported)
            .unwrap()
            .apply(&mut config)
            .unwrap();
        assert_eq!(config.proxies[0].protected_password, ciphertext);
    }
}
