use super::{Command, State, model};
use crate::{MainWindow, ProxyRow};
use anyhow::{Context, Result, ensure};
use slint::{ComponentHandle, Model};
use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    sync::{Arc, Mutex, mpsc::SyncSender},
};
use true_proxy::{
    config::{Config, Proxy},
    platform, socks,
};

#[derive(Clone)]
pub struct Health {
    key: String,
    tcp: bool,
    udp: bool,
    latency: u128,
    error: String,
}
pub type Statuses = HashMap<String, Health>;

pub fn key(proxy: &Proxy) -> String {
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    (
        &proxy.id,
        &proxy.host,
        proxy.port,
        &proxy.username,
        &proxy.protected_password,
    )
        .hash(&mut hash);
    format!("{:x}", hash.finish())
}
pub fn row(proxy: &Proxy, statuses: &Statuses) -> ProxyRow {
    let key = key(proxy);
    let health = statuses.get(&proxy.id).filter(|h| h.key == key);
    ProxyRow {
        id: proxy.id.clone().into(),
        key: key.into(),
        name: proxy.name.clone().into(),
        address: format!("{}:{}", proxy.host, proxy.port).into(),
        health: health.map_or(0, |h| if h.tcp { 2 } else { 3 }),
        udp: health.is_some_and(|h| h.udp),
        status: health
            .map_or_else(String::new, |h| {
                if h.tcp {
                    format!("{} мс", h.latency)
                } else {
                    h.error.clone()
                }
            })
            .into(),
    }
}
pub async fn check(proxy: &Proxy) -> Health {
    let mut health = Health {
        key: key(proxy),
        tcp: false,
        udp: false,
        latency: 0,
        error: String::new(),
    };
    match socks::probe(proxy).await {
        Ok((latency, udp)) => {
            health.tcp = true;
            health.udp = udp;
            health.latency = latency;
        }
        Err(error) => health.error = format!("{error:#}"),
    }
    health
}
pub fn publish(
    weak: slint::Weak<MainWindow>,
    statuses: &Arc<Mutex<Statuses>>,
    proxy: Proxy,
    health: Health,
    token: Option<String>,
) {
    if token.is_none() {
        let mut statuses = statuses.lock().unwrap();
        // Deleted profiles and old in-flight probes cannot grow the cache indefinitely.
        if statuses.len() < 64 || statuses.contains_key(&proxy.id) {
            statuses.insert(proxy.id.clone(), health.clone());
        }
    }
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            if let Some(token) = token {
                ui.set_probe_busy(false);
                if ui.get_form_probe_token() == token {
                    ui.set_form_probe_health(if health.tcp { 2 } else { 3 });
                    ui.set_form_probe_status(
                        if health.tcp {
                            format!(
                                "Доступен · {} мс{}",
                                health.latency,
                                if health.udp {
                                    ""
                                } else {
                                    " · UDP недоступен"
                                }
                            )
                        } else {
                            health.error
                        }
                        .into(),
                    );
                }
            } else {
                let rows = ui
                    .get_proxies()
                    .iter()
                    .map(|mut row| {
                        if row.id == proxy.id && row.key == health.key {
                            row.health = if health.tcp { 2 } else { 3 };
                            row.udp = health.udp;
                            row.status = if health.tcp {
                                format!("{} мс", health.latency)
                            } else {
                                health.error.clone()
                            }
                            .into();
                        }
                        row
                    })
                    .collect();
                ui.set_proxies(model(rows));
            }
        }
    });
}
pub fn from_form(ui: &MainWindow, config: &Config) -> Result<Proxy> {
    let port = ui
        .get_form_port()
        .trim()
        .parse::<u16>()
        .context("Порт должен быть числом 1–65535")?;
    ensure!(port > 0, "Порт не может быть нулевым");
    let mut proxy = Proxy {
        id: if ui.get_form_id().is_empty() {
            super::id()
        } else {
            ui.get_form_id().to_string()
        },
        name: ui.get_form_name().trim().into(),
        host: ui.get_form_host().trim().trim_matches(['[', ']']).into(),
        port,
        username: if ui.get_form_auth() {
            ui.get_form_username().to_string()
        } else {
            String::new()
        },
        protected_password: None,
    };
    if ui.get_form_auth() {
        proxy.protected_password = if ui.get_form_password().is_empty() {
            config
                .proxy(&proxy.id)
                .ok()
                .and_then(|p| p.protected_password.clone())
        } else {
            Some(platform::protect(&ui.get_form_password())?)
        };
    }
    Ok(proxy)
}
pub fn wire_form_probe(ui: &MainWindow, state: State, sender: SyncSender<Command>, preview: bool) {
    let weak = ui.as_weak();
    ui.on_proxy_form_edited(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_form_probe_token("".into());
            ui.set_form_probe_status("".into());
            ui.set_form_probe_health(0);
        }
    });
    let weak = ui.as_weak();
    ui.on_probe_proxy_form(move || {
        if let Some(ui) = weak.upgrade() {
            if ui.get_probe_busy() {
                return;
            }
            let result = (|| {
                ensure!(!preview, "В режиме проверки UI сетевые проверки отключены");
                let mut proxy = from_form(&ui, &state.borrow())?;
                if proxy.name.is_empty() {
                    proxy.name = "Проверка".into();
                }
                Config {
                    proxies: vec![proxy.clone()],
                    ..Config::default()
                }
                .validate()?;
                let token = super::id();
                sender
                    .try_send(Command::Probe(proxy, Some(token.clone())))
                    .context("Проверка уже выполняется")?;
                ui.set_form_probe_token(token.into());
                ui.set_form_probe_health(0);
                ui.set_form_probe_status("Проверяем…".into());
                ui.set_probe_busy(true);
                Ok(())
            })();
            if let Err(error) = result {
                ui.set_form_probe_health(3);
                ui.set_form_probe_status(format!("{error:#}").into());
            }
        }
    });
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    #[test]
    fn unsaved_form_uses_current_endpoint_and_preserves_secret_without_saving() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        let secret = platform::protect("private").unwrap();
        let original = Proxy {
            id: "one".into(),
            name: "Original".into(),
            host: "127.0.0.1".into(),
            port: 1080,
            username: "old".into(),
            protected_password: Some(secret.clone()),
        };
        let config = Config {
            proxies: vec![original.clone()],
            ..Config::default()
        };
        ui.set_form_id("one".into());
        ui.set_form_host("localhost".into());
        ui.set_form_port("2080".into());
        ui.set_form_auth(true);
        ui.set_form_username("new".into());
        let proxy = from_form(&ui, &config).unwrap();
        assert_eq!(proxy.port, 2080);
        assert_eq!(proxy.host, "localhost");
        assert_eq!(proxy.username, "new");
        assert_eq!(proxy.protected_password, Some(secret));
        assert_eq!(config.proxies[0].port, 1080);
        let mut statuses = Statuses::new();
        statuses.insert(
            original.id.clone(),
            Health {
                key: key(&original),
                tcp: true,
                udp: false,
                latency: 5,
                error: String::new(),
            },
        );
        assert_eq!(row(&original, &statuses).health, 2);
        assert!(!row(&original, &statuses).udp);
        assert_eq!(
            row(&proxy, &statuses).health,
            0,
            "Old check cannot attest to edited endpoint/authentication"
        );
        ui.set_form_auth(false);
        assert!(
            from_form(&ui, &config)
                .unwrap()
                .protected_password
                .is_none()
        );
    }
}
