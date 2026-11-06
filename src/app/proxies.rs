use super::{Command, State};
use crate::{MainWindow, ProxyRow};
use anyhow::{Context, Result, ensure};
use slint::{ComponentHandle, Model, SharedString, VecModel};
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
    location: Option<String>,
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
    let mut row = ProxyRow {
        id: proxy.id.clone().into(),
        key: key.into(),
        name: proxy.name.clone().into(),
        address: format!("{}:{}", proxy.host, proxy.port).into(),
        ..ProxyRow::default()
    };
    if let Some(health) = health {
        update_health(&mut row, health);
    }
    row
}

fn update_health(row: &mut ProxyRow, health: &Health) {
    row.health = if health.tcp { 2 } else { 3 };
    row.udp = health.udp;
    row.location = health.location.as_deref().unwrap_or_default().into();
    row.status = if health.tcp {
        format!("{} ms", health.latency)
    } else {
        health.error.clone()
    }
    .into();
}

pub fn refresh_table(ui: &MainWindow) {
    let query = ui.get_proxy_query().trim().to_lowercase();
    let rows = ui
        .get_proxies()
        .iter()
        .filter(|row| {
            query.is_empty()
                || row.name.to_lowercase().contains(&query)
                || row.address.to_lowercase().contains(&query)
        })
        .collect();
    ui.set_visible_proxies(super::model(rows));
    set_selection(ui, ui.get_selected_proxy_ids().iter().collect());
}

// Selection is scoped to the visible rows, including after a search or edit.
fn set_selection(ui: &MainWindow, requested: Vec<SharedString>) {
    let rows = ui.get_visible_proxies();
    let mut ids = Vec::new();
    let flags = rows
        .iter()
        .map(|row| {
            let checked = requested.contains(&row.id);
            if checked {
                ids.push(row.id);
            }
            checked
        })
        .collect();
    ui.set_proxy_selection_state(if ids.is_empty() {
        0
    } else if ids.len() == rows.row_count() {
        2
    } else {
        1
    });
    ui.set_proxy_selection(super::model(flags));
    ui.set_selected_proxy_ids(super::model(ids));
}

pub fn wire_table(ui: &MainWindow) {
    let weak = ui.as_weak();
    ui.on_filter_proxies(move || {
        if let Some(ui) = weak.upgrade() {
            refresh_table(&ui);
        }
    });
    let weak = ui.as_weak();
    ui.on_toggle_proxy_selection(move |id, checked| {
        if let Some(ui) = weak.upgrade() {
            let mut ids: Vec<_> = ui.get_selected_proxy_ids().iter().collect();
            ids.retain(|existing| existing != &id);
            if checked {
                ids.push(id);
            }
            set_selection(&ui, ids);
        }
    });
    let weak = ui.as_weak();
    ui.on_select_visible_proxies(move |checked| {
        if let Some(ui) = weak.upgrade() {
            let ids = if checked {
                ui.get_visible_proxies().iter().map(|row| row.id).collect()
            } else {
                Vec::new()
            };
            set_selection(&ui, ids);
        }
    });
}
pub async fn check(proxy: &Proxy) -> Health {
    let mut health = Health {
        key: key(proxy),
        tcp: false,
        udp: false,
        latency: 0,
        location: None,
        error: String::new(),
    };
    match socks::probe(proxy).await {
        Ok((latency, udp)) => {
            health.tcp = true;
            health.udp = udp;
            health.latency = latency;
            health.location = platform::proxy_location(proxy).await;
        }
        Err(error) => health.error = format!("{error:#}"),
    }
    health
}

fn result_text(name: &str, health: &Health) -> (String, bool) {
    if health.tcp {
        let mut message = format!(
            "{name}: TCP available, {} ms · UDP {}",
            health.latency,
            if health.udp {
                "available"
            } else {
                "unavailable"
            }
        );
        if let Some(location) = &health.location {
            message.push_str(" · ");
            message.push_str(location);
        }
        (message, !health.udp)
    } else {
        (
            format!("{name}: Connection failed · {}", health.error),
            true,
        )
    }
}

pub(super) fn preview_statuses(config: &Config) -> Statuses {
    config
        .proxies
        .iter()
        .zip([("Ashburn, US", 98), ("Nuremberg, DE", 19)])
        .map(|(proxy, (location, latency))| {
            (
                proxy.id.clone(),
                Health {
                    key: key(proxy),
                    tcp: true,
                    udp: true,
                    latency,
                    location: Some(location.into()),
                    error: String::new(),
                },
            )
        })
        .collect()
}

fn apply_result(ui: &MainWindow, proxy: &Proxy, health: &Health, token: Option<&str>) {
    if let Some(token) = token {
        let current = ui.get_form_probe_token();
        if current == token {
            ui.set_probe_busy(false);
            ui.set_form_probe_status("".into());
            ui.set_form_probe_health(0);
            if ui.get_dialog() == 1 {
                let (message, error) = result_text(&proxy.name, health);
                super::show_toast(ui, message, error);
            }
        } else if current.is_empty() {
            // Editing or closing invalidates the display token, but the one
            // in-flight check still needs to release its busy state.
            ui.set_probe_busy(false);
        }
    } else {
        ui.set_probe_busy(false);
        let rows = ui.get_proxies();
        if let Some((index, mut row)) = rows
            .iter()
            .enumerate()
            .find(|(_, row)| row.id == proxy.id && row.key == health.key)
        {
            let (message, error) = result_text(&row.name, health);
            update_health(&mut row, health);
            if let Some(model) = rows.as_any().downcast_ref::<VecModel<ProxyRow>>() {
                model.set_row_data(index, row);
            } else {
                let mut updated: Vec<_> = rows.iter().collect();
                updated[index] = row;
                ui.set_proxies(super::model(updated));
            }
            refresh_table(ui);
            super::show_toast(ui, message, error);
        }
    }
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
            apply_result(&ui, &proxy, &health, token.as_deref());
        }
    });
}
pub fn from_form(ui: &MainWindow, config: &Config) -> Result<Proxy> {
    let port = ui
        .get_form_port()
        .trim()
        .parse::<u16>()
        .context("Enter a port between 1 and 65535")?;
    ensure!(port > 0, "The port must be greater than zero");
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
                ensure!(!preview, "Network checks are disabled in UI preview mode");
                let mut proxy = from_form(&ui, &state.borrow())?;
                if proxy.name.is_empty() {
                    proxy.name = "Connection test".into();
                }
                Config {
                    proxies: vec![proxy.clone()],
                    ..Config::default()
                }
                .validate()?;
                let token = super::id();
                sender
                    .try_send(Command::Probe(proxy, Some(token.clone())))
                    .context("A connection check is already running")?;
                ui.set_form_probe_token(token.into());
                ui.set_form_probe_health(0);
                ui.set_form_probe_status("Checking…".into());
                ui.set_probe_busy(true);
                Ok(())
            })();
            if let Err(error) = result {
                ui.set_form_probe_health(0);
                ui.set_form_probe_status("".into());
                super::show_toast(&ui, format!("{error:#}"), true);
            }
        }
    });
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    use i_slint_backend_testing::ElementHandle;
    use slint::platform::{PointerEventButton, WindowEvent};

    fn fixture_proxy() -> Proxy {
        Proxy {
            id: "test".into(),
            name: "Proxy".into(),
            host: "127.0.0.1".into(),
            port: 1080,
            username: String::new(),
            protected_password: None,
        }
    }

    #[test]
    fn first_click_selects_proxies_and_search_limits_selection_to_visible_rows() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1000., 700.));
        ui.set_page(2);
        let primary = fixture_proxy();
        let backup = Proxy {
            id: "backup".into(),
            name: "Backup".into(),
            ..primary.clone()
        };
        let statuses = Statuses::new();
        ui.set_proxies(super::super::model(vec![
            row(&primary, &statuses),
            row(&backup, &statuses),
        ]));
        wire_table(&ui);
        refresh_table(&ui);
        ui.show().unwrap();

        let click = |label| {
            ElementHandle::find_by_accessible_label(&ui, label)
                .next()
                .unwrap_or_else(|| panic!("Missing control {label}"))
                .mock_single_click(PointerEventButton::Left);
        };
        click("Select all proxies");
        assert_eq!(ui.get_proxy_selection_state(), 2);
        click("Select proxy Proxy");
        assert_eq!(ui.get_proxy_selection_state(), 1);
        click("Select all proxies");
        click("Search proxies");
        for text in ["B", "A"] {
            ui.window()
                .dispatch_event(WindowEvent::KeyPressed { text: text.into() });
        }
        assert_eq!(ui.get_visible_proxies().row_count(), 1);
        assert_eq!(ui.get_selected_proxy_ids().row_count(), 1);
        assert_eq!(ui.get_selected_proxy_ids().row_data(0).unwrap(), "backup");
    }

    #[test]
    fn manual_saved_results_only_notify_for_the_current_proxy_key() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        let proxy = fixture_proxy();
        let mut renamed = proxy.clone();
        renamed.name = "Current name".into();
        ui.set_proxies(super::super::model(vec![row(&renamed, &Statuses::new())]));
        let mut health = Health {
            key: key(&proxy),
            tcp: true,
            udp: true,
            latency: 7,
            location: Some("Berlin, DE".into()),
            error: String::new(),
        };
        apply_result(&ui, &proxy, &health, None);
        assert_eq!(ui.get_visible_proxies().row_data(0).unwrap().status, "7 ms");
        assert_eq!(ui.get_proxies().row_data(0).unwrap().location, "Berlin, DE");
        assert!(ui.get_toast().starts_with("Current name:"));
        assert!(
            ui.get_toast().contains("TCP available")
                && ui.get_toast().contains("7 ms")
                && ui.get_toast().contains("UDP available")
        );
        assert!(!ui.get_toast_error());
        let previous = ui.get_toast();
        health.key = "old endpoint".into();
        health.tcp = false;
        health.location = None;
        health.error = "connection refused".into();
        apply_result(&ui, &proxy, &health, None);
        assert_eq!(ui.get_visible_proxies().row_data(0).unwrap().status, "7 ms");
        assert_eq!(ui.get_proxies().row_data(0).unwrap().location, "Berlin, DE");
        assert_eq!(
            ui.get_toast(),
            previous,
            "An edited endpoint must not receive its old result"
        );
        health.key = key(&proxy);
        ui.set_proxies(super::super::model(vec![]));
        apply_result(&ui, &proxy, &health, None);
        assert_eq!(ui.get_toast(), previous, "A deleted proxy must not notify");
        ui.set_proxies(super::super::model(vec![row(&proxy, &Statuses::new())]));
        apply_result(&ui, &proxy, &health, None);
        assert!(ui.get_toast_error() && ui.get_toast().contains("connection refused"));
        health.tcp = true;
        health.udp = false;
        apply_result(&ui, &proxy, &health, None);
        assert!(
            ui.get_toast_error()
                && ui.get_toast().contains("TCP available")
                && ui.get_toast().contains("UDP unavailable")
        );
    }

    #[test]
    fn form_result_is_a_toast_and_stale_tokens_do_not_replace_a_newer_check() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        let proxy = fixture_proxy();
        let health = Health {
            key: key(&proxy),
            tcp: true,
            udp: true,
            latency: 3,
            location: None,
            error: String::new(),
        };
        ui.set_dialog(1);
        ui.set_form_probe_token("current".into());
        ui.set_form_probe_status("Checking…".into());
        ui.set_probe_busy(true);
        apply_result(&ui, &proxy, &health, Some("old"));
        assert!(ui.get_toast().is_empty() && ui.get_probe_busy());
        assert_eq!(ui.get_form_probe_status(), "Checking…");
        apply_result(&ui, &proxy, &health, Some("current"));
        assert!(!ui.get_toast().is_empty() && !ui.get_probe_busy());
        assert!(ui.get_form_probe_status().is_empty());
        assert!(!ui.get_toast_error());
        let previous = ui.get_toast();
        ui.set_dialog(0);
        ui.set_form_probe_token("".into());
        ui.set_probe_busy(true);
        apply_result(&ui, &proxy, &health, Some("current"));
        assert_eq!(
            ui.get_toast(),
            previous,
            "Closing the form invalidates its notification"
        );
        assert!(!ui.get_probe_busy());
    }

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
                location: None,
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
