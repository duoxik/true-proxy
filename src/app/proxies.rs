use super::{Command, State};
use crate::{MainWindow, ProxyRow};
use anyhow::{Context, Result, ensure};
use slint::{ComponentHandle, Model, SharedString, VecModel};
use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    sync::{Arc, Mutex, mpsc::SyncSender},
    thread,
    time::{Duration, Instant},
};
use true_proxy::{
    config::{Config, Proxy},
    platform, socks,
};

#[derive(Clone)]
pub struct Health {
    key: String,
    checked_at: Instant,
    tcp: bool,
    udp: bool,
    latency: u128,
    location: Option<String>,
    error: String,
}
pub type Statuses = HashMap<String, Health>;

const AUTO_INTERVAL: Duration = Duration::from_secs(20);
const AUTO_CONCURRENCY: usize = 4;

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
    row.flag_index = flag_index(&row.location);
    row.status = if health.tcp {
        format!("{} ms", health.latency)
    } else {
        health.error.clone()
    }
    .into();
}

fn flag_index(location: &str) -> i32 {
    let country = location.rsplit(", ").next().unwrap_or_default();
    include_str!("../../assets/country-flags.txt")
        .split_ascii_whitespace()
        .position(|code| code == country)
        .map_or(0, |index| index as i32 + 1)
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
    measure(proxy, Instant::now()).await
}

async fn measure(proxy: &Proxy, checked_at: Instant) -> Health {
    let mut health = Health {
        key: key(proxy),
        checked_at,
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

fn result_text(health: &Health) -> String {
    if health.tcp {
        let mut message = format!(
            "TCP available, {} ms · UDP {}",
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
        message
    } else {
        format!("Connection failed · {}", health.error)
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
                    checked_at: Instant::now(),
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

fn apply_form_result(ui: &MainWindow, health: &Health, token: &str) {
    let current = ui.get_form_probe_token();
    if current == token {
        ui.set_probe_busy(false);
        if ui.get_dialog() == 1 {
            ui.set_form_probe_status(result_text(health).into());
            ui.set_form_probe_health(if health.tcp { 2 } else { 3 });
        }
    } else if current.is_empty() {
        // Editing or closing invalidates the display token, but the one
        // in-flight check still needs to release its busy state.
        ui.set_probe_busy(false);
    }
}

fn apply_saved_result(ui: &MainWindow, statuses: &Mutex<Statuses>, id: &str, mut health: Health) {
    let rows = ui.get_proxies();
    let Some((index, mut row)) = rows
        .iter()
        .enumerate()
        .find(|(_, row)| row.id == id && row.key == health.key)
    else {
        return;
    };
    {
        let mut cache = statuses.lock().unwrap();
        if let Some(previous) = cache.get(id).filter(|previous| previous.key == health.key) {
            if previous.checked_at > health.checked_at {
                return;
            }
            if health.location.is_none() {
                health.location.clone_from(&previous.location);
            }
        }
        // Deleted proxies must not fill the cache after repeated profile edits.
        if cache.len() >= 64 && !cache.contains_key(id) {
            cache.retain(|id, _| rows.iter().any(|row| row.id == id.as_str()));
        }
        cache.insert(id.into(), health.clone());
    }
    update_health(&mut row, &health);
    if rows.row_data(index).as_ref() != Some(&row) {
        if let Some(model) = rows.as_any().downcast_ref::<VecModel<ProxyRow>>() {
            model.set_row_data(index, row.clone());
        } else {
            let mut updated: Vec<_> = rows.iter().collect();
            updated[index] = row.clone();
            ui.set_proxies(super::model(updated));
        }
        let visible = ui.get_visible_proxies();
        if let Some((index, _)) = visible
            .iter()
            .enumerate()
            .find(|(_, old)| old.id == id && old != &row)
        {
            if let Some(model) = visible.as_any().downcast_ref::<VecModel<ProxyRow>>() {
                model.set_row_data(index, row.clone());
            } else {
                refresh_table(ui);
            }
        }
    }
}

pub fn publish(
    weak: slint::Weak<MainWindow>,
    statuses: Arc<Mutex<Statuses>>,
    id: String,
    health: Health,
    token: Option<String>,
) {
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            if let Some(token) = token {
                apply_form_result(&ui, &health, &token);
            } else {
                ui.set_probe_busy(false);
                apply_saved_result(&ui, &statuses, &id, health);
            }
        }
    });
}

pub fn wire_automatic(
    ui: &MainWindow,
    state: State,
    statuses: Arc<Mutex<Statuses>>,
) -> slint::Timer {
    let weak = ui.as_weak();
    let mut batch = None::<thread::JoinHandle<()>>;
    let mut run = move || {
        let Some(ui) = weak.upgrade() else { return };
        if ui.get_probe_busy() || batch.as_ref().is_some_and(|batch| !batch.is_finished()) {
            return;
        }
        let proxies = state.borrow().proxies.clone();
        if proxies.is_empty() {
            return;
        }
        let started = Instant::now();
        let weak = weak.clone();
        let statuses = statuses.clone();
        batch = thread::Builder::new()
            .name("automatic-proxy-probes".into())
            .spawn(move || {
                if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    runtime.block_on(check_automatic(weak, statuses, proxies, started));
                }
            })
            .ok();
    };
    run();
    let timer = slint::Timer::default();
    timer.start(slint::TimerMode::Repeated, AUTO_INTERVAL, run);
    timer
}

async fn check_automatic(
    weak: slint::Weak<MainWindow>,
    statuses: Arc<Mutex<Statuses>>,
    proxies: Vec<Proxy>,
    started: Instant,
) {
    let mut proxies = proxies.into_iter();
    let mut checks = tokio::task::JoinSet::new();
    loop {
        while checks.len() < AUTO_CONCURRENCY {
            let Some(proxy) = proxies.next() else { break };
            checks.spawn(async move {
                let health = measure(&proxy, started).await;
                (proxy.id, health)
            });
        }
        let Some(result) = checks.join_next().await else {
            break;
        };
        if let Ok((id, health)) = result {
            let weak = weak.clone();
            let statuses = statuses.clone();
            if slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    apply_saved_result(&ui, &statuses, &id, health);
                }
            })
            .is_err()
            {
                break;
            }
        }
    }
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
                ui.set_form_probe_health(3);
                ui.set_form_probe_status(format!("{error:#}").into());
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
    fn saved_results_preserve_location_and_ignore_stale_checks() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        let proxy = fixture_proxy();
        ui.set_proxies(super::super::model(vec![row(&proxy, &Statuses::new())]));
        refresh_table(&ui);
        let statuses = Mutex::new(Statuses::new());
        let mut health = Health {
            key: key(&proxy),
            checked_at: Instant::now(),
            tcp: true,
            udp: true,
            latency: 7,
            location: Some("Berlin, DE".into()),
            error: String::new(),
        };
        apply_saved_result(&ui, &statuses, &proxy.id, health.clone());
        assert_eq!(ui.get_visible_proxies().row_data(0).unwrap().status, "7 ms");
        assert_eq!(ui.get_proxies().row_data(0).unwrap().location, "Berlin, DE");
        let old_result = health.clone();
        health.checked_at += Duration::from_secs(1);
        health.key = "old endpoint".into();
        health.tcp = false;
        health.location = None;
        health.error = "connection refused".into();
        apply_saved_result(&ui, &statuses, &proxy.id, health.clone());
        assert_eq!(ui.get_visible_proxies().row_data(0).unwrap().status, "7 ms");
        health.key = key(&proxy);
        ui.set_probe_busy(true);
        apply_saved_result(&ui, &statuses, &proxy.id, health.clone());
        apply_saved_result(&ui, &statuses, &proxy.id, old_result);
        let visible = ui.get_visible_proxies().row_data(0).unwrap();
        assert_eq!(visible.status, "connection refused");
        assert_eq!(visible.location, "Berlin, DE");
        assert_eq!(visible.health, 3);
        assert!(ui.get_probe_busy() && ui.get_toast().is_empty());
        ui.set_proxies(super::super::model(vec![]));
        health.checked_at += Duration::from_secs(1);
        apply_saved_result(&ui, &statuses, &proxy.id, health.clone());
        assert!(
            statuses.lock().unwrap()[&proxy.id].checked_at < health.checked_at,
            "A deleted proxy must not receive an in-flight result"
        );
    }

    #[test]
    fn form_result_stays_inline_and_stale_tokens_do_not_replace_a_newer_check() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        let proxy = fixture_proxy();
        let health = Health {
            key: key(&proxy),
            checked_at: Instant::now(),
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
        apply_form_result(&ui, &health, "old");
        assert!(ui.get_toast().is_empty() && ui.get_probe_busy());
        assert_eq!(ui.get_form_probe_status(), "Checking…");
        apply_form_result(&ui, &health, "current");
        assert!(ui.get_toast().is_empty() && !ui.get_probe_busy());
        assert_eq!(
            ui.get_form_probe_status(),
            "TCP available, 3 ms · UDP available"
        );
        assert_eq!(ui.get_form_probe_health(), 2);
        ui.set_dialog(0);
        ui.set_form_probe_token("".into());
        ui.set_form_probe_status("".into());
        ui.set_probe_busy(true);
        apply_form_result(&ui, &health, "current");
        assert_eq!(
            ui.get_form_probe_status(),
            "",
            "Closing the form invalidates its result"
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
                checked_at: Instant::now(),
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
