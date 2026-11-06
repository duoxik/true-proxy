use super::{model, routing};
use crate::{ConnectionFilterOption, ConnectionMonitor, MainWindow};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use slint::{ComponentHandle, Model, ModelRc, VecModel};
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{ErrorKind, Read, Write},
    path::Path,
};
use true_proxy::{config::Action, connections::Status, platform};

const ALL: &str = "all";
const PROXY: &str = "proxy";
const DIRECT: &str = "direct";
const BLOCK: &str = "block";
const ROUTES: [(&str, &str); 3] = [(PROXY, "Proxy"), (DIRECT, "Direct"), (BLOCK, "Blocked")];
const STATUSES: [Status; 7] = [
    Status::Connecting,
    Status::Active,
    Status::Closing,
    Status::Closed,
    Status::Failed,
    Status::Blocked,
    Status::Stopped,
];

#[derive(Deserialize, Serialize)]
pub struct Preferences {
    routes: Vec<String>,
    statuses: Vec<String>,
}

impl Preferences {
    pub fn load(path: &Path) -> Result<Option<Self>> {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut contents = Vec::new();
        file.take(4097).read_to_end(&mut contents)?;
        ensure!(contents.len() <= 4096, "Connection filters exceed 4 KiB");
        let preferences: Self =
            serde_json::from_slice(&contents).context("Could not read connection filters")?;
        ensure!(
            preferences.routes == [ALL]
                || ROUTES
                    .iter()
                    .filter(|(route, _)| preferences
                        .routes
                        .iter()
                        .any(|key| key.as_str() == *route))
                    .count()
                    == preferences.routes.len(),
            "Invalid route filters"
        );
        ensure!(
            STATUSES
                .iter()
                .filter(|status| preferences.statuses.contains(&status_key(**status)))
                .count()
                == preferences.statuses.len(),
            "Invalid status filters"
        );
        Ok(Some(preferences))
    }

    pub fn apply(self, ui: &MainWindow) {
        let monitor = ui.global::<ConnectionMonitor>();
        let all = self.routes == [ALL] || self.routes.len() == ROUTES.len();
        monitor.set_connection_routes_all(all);
        monitor.set_connection_route_selection(routing::strings(if all {
            vec![]
        } else {
            self.routes
        }));
        monitor.set_connection_status_selection(routing::strings(self.statuses));
    }

    pub fn save(ui: &MainWindow, path: &Path) -> Result<()> {
        let monitor = ui.global::<ConnectionMonitor>();
        let preferences = Self {
            routes: if monitor.get_connection_routes_all() {
                vec![ALL.into()]
            } else {
                routing::values(monitor.get_connection_route_selection())
            },
            statuses: routing::values(monitor.get_connection_status_selection()),
        };
        fs::create_dir_all(
            path.parent()
                .context("Missing connection filters directory")?,
        )?;
        let temporary = path.with_extension("tmp");
        let mut file = File::create(&temporary)?;
        file.write_all(&serde_json::to_vec(&preferences)?)?;
        file.sync_all()?;
        drop(file);
        platform::replace_file(&temporary, path).context("Could not save connection filters")
    }
}

pub fn route_key(action: &Action) -> &'static str {
    match action {
        Action::Direct => DIRECT,
        Action::Block => BLOCK,
        Action::Proxy(_) => PROXY,
    }
}
pub fn status_key(status: Status) -> String {
    (status as u8).to_string()
}
pub fn all_statuses() -> Vec<String> {
    STATUSES.into_iter().map(status_key).collect()
}
pub fn default_statuses() -> Vec<String> {
    STATUSES
        .into_iter()
        .filter(|status| !status.finished())
        .map(status_key)
        .collect()
}
pub fn selected_statuses(ui: &MainWindow) -> HashSet<String> {
    routing::values(
        ui.global::<ConnectionMonitor>()
            .get_connection_status_selection(),
    )
    .into_iter()
    .filter(|key| STATUSES.iter().any(|status| status_key(*status) == *key))
    .collect()
}
pub fn selected_finished_statuses(ui: &MainWindow) -> Vec<Status> {
    let selected = selected_statuses(ui);
    STATUSES
        .into_iter()
        .filter(|status| status.finished() && selected.contains(&status_key(*status)))
        .collect()
}
fn option(key: &str, label: &str, checked: bool) -> ConnectionFilterOption {
    ConnectionFilterOption {
        key: key.into(),
        label: label.into(),
        checked,
    }
}
pub fn refresh(ui: &MainWindow) {
    let monitor = ui.global::<ConnectionMonitor>();
    let all = monitor.get_connection_routes_all();
    let selected = routing::values(monitor.get_connection_route_selection());
    let mut choices = vec![option(ALL, "All", all)];
    choices.extend(
        ROUTES.into_iter().map(|(key, label)| {
            option(key, label, all || selected.iter().any(|value| value == key))
        }),
    );
    let summary = if all {
        "All".into()
    } else if let [key] = selected.as_slice()
        && let Some((_, label)) = ROUTES.iter().find(|(route, _)| *route == key.as_str())
    {
        (*label).into()
    } else {
        selected.len().to_string().into()
    };
    monitor.set_connection_route_summary(summary);
    monitor
        .set_connection_route_filters(reconcile(monitor.get_connection_route_filters(), choices));

    let statuses = selected_statuses(ui);
    let all_statuses = statuses.len() == STATUSES.len();
    let mut choices = vec![option(ALL, "All", all_statuses)];
    choices.extend(STATUSES.iter().map(|status| {
        let key = status_key(*status);
        option(&key, status.label(), statuses.contains(&key))
    }));
    monitor
        .set_connection_status_filters(reconcile(monitor.get_connection_status_filters(), choices));
    let default_statuses = statuses.len() == STATUSES.iter().filter(|s| !s.finished()).count()
        && STATUSES
            .iter()
            .all(|status| status.finished() || statuses.contains(&status_key(*status)));
    monitor.set_connection_filters_default(
        monitor.get_connection_query().is_empty()
            && !all
            && selected == [PROXY]
            && default_statuses,
    );
}

/// Update existing checkbox rows in place to preserve focus and scroll position.
fn reconcile(
    previous: ModelRc<ConnectionFilterOption>,
    choices: Vec<ConnectionFilterOption>,
) -> ModelRc<ConnectionFilterOption> {
    if previous.row_count() == choices.len()
        && let Some(model) = previous
            .as_any()
            .downcast_ref::<VecModel<ConnectionFilterOption>>()
    {
        for (index, row) in choices.into_iter().enumerate() {
            if previous.row_data(index).as_ref() != Some(&row) {
                model.set_row_data(index, row);
            }
        }
        previous
    } else {
        model(choices)
    }
}

pub fn toggle_route(ui: &MainWindow, key: &str, checked: bool) {
    let monitor = ui.global::<ConnectionMonitor>();
    if key == ALL {
        monitor.set_connection_routes_all(checked);
        monitor.set_connection_route_selection(routing::strings(vec![]));
        return;
    }
    if !ROUTES.iter().any(|(route, _)| *route == key) {
        return;
    }
    let was_all = monitor.get_connection_routes_all();
    let previous = routing::values(monitor.get_connection_route_selection());
    let mut selected = ROUTES
        .into_iter()
        .map(|(route, _)| route)
        .filter(|route| {
            if *route == key {
                checked
            } else {
                was_all || previous.iter().any(|value| value == *route)
            }
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let all = selected.len() == ROUTES.len();
    monitor.set_connection_routes_all(all);
    if all {
        selected.clear();
    }
    monitor.set_connection_route_selection(routing::strings(selected));
}

pub fn toggle_status(ui: &MainWindow, key: &str, checked: bool) {
    let mut selected = selected_statuses(ui);
    if key == ALL {
        selected = if checked {
            all_statuses().into_iter().collect()
        } else {
            HashSet::new()
        };
    } else if STATUSES.iter().any(|status| status_key(*status) == key) {
        if checked {
            selected.insert(key.into());
        } else {
            selected.remove(key);
        }
    } else {
        return;
    }
    let mut selected = selected.into_iter().collect::<Vec<_>>();
    selected.sort();
    ui.global::<ConnectionMonitor>()
        .set_connection_status_selection(routing::strings(selected));
}

pub fn reset(ui: &MainWindow) {
    let monitor = ui.global::<ConnectionMonitor>();
    monitor.set_connection_query("".into());
    monitor.set_connection_routes_all(false);
    monitor.set_connection_route_selection(routing::strings(vec![PROXY.into()]));
    monitor.set_connection_status_selection(routing::strings(default_statuses()));
}
