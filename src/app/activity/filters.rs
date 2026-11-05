use super::{model, routing};
use crate::{ConnectionFilterOption, ConnectionFilterRow, ConnectionsWindow};
use slint::{Model, ModelRc, VecModel};
use std::collections::{BTreeMap, HashSet};
use true_proxy::{
    config::Action,
    connections::{Snapshot, Status},
};

pub const ALL: &str = "all";
const MAX_SELECTED_ROUTES: usize =
    64 + true_proxy::connections::MAX_ACTIVE + true_proxy::connections::MAX_COMPLETED + 2;
pub const STATUSES: [Status; 7] = [
    Status::Connecting,
    Status::Active,
    Status::Closing,
    Status::Closed,
    Status::Failed,
    Status::Blocked,
    Status::Stopped,
];

pub fn route_key(action: &Action) -> String {
    match action {
        Action::Direct => "direct".into(),
        Action::Block => "block".into(),
        Action::Proxy(id) => format!("proxy:{id}"),
    }
}
pub fn status_key(status: Status) -> String {
    (status as u8).to_string()
}
pub fn default_statuses() -> Vec<String> {
    STATUSES[..3]
        .iter()
        .map(|status| status_key(*status))
        .collect()
}
pub fn selected_statuses(ui: &ConnectionsWindow) -> HashSet<String> {
    routing::values(ui.get_connection_status_selection())
        .into_iter()
        .filter(|key| STATUSES.iter().any(|status| status_key(*status) == *key))
        .collect()
}
pub fn history_enabled(ui: &ConnectionsWindow) -> bool {
    let selected = selected_statuses(ui);
    STATUSES
        .iter()
        .any(|status| status.finished() && selected.contains(&status_key(*status)))
}
pub fn is_default(ui: &ConnectionsWindow) -> bool {
    ui.get_connection_query().is_empty()
        && ui.get_connection_routes_all()
        && selected_statuses(ui) == default_statuses().into_iter().collect()
}
fn option(key: String, label: String, checked: bool) -> ConnectionFilterOption {
    ConnectionFilterOption {
        key: key.into(),
        label: label.into(),
        checked,
    }
}
fn options(rows: ModelRc<ConnectionFilterRow>) -> Vec<ConnectionFilterOption> {
    rows.iter()
        .flat_map(|row| row.options.iter().collect::<Vec<_>>())
        .collect()
}

pub fn refresh(ui: &ConnectionsWindow, snapshots: &[Snapshot]) {
    let all = ui.get_connection_routes_all();
    let selected = routing::values(ui.get_connection_route_selection())
        .into_iter()
        .collect::<HashSet<_>>();
    let mut choices = vec![option(ALL.into(), "Все".into(), all)];
    let mut known = HashSet::new();
    for proxy in ui.get_proxies().iter().take(64) {
        if known.insert(proxy.id.to_string()) {
            let key = route_key(&Action::Proxy(proxy.id.to_string()));
            choices.push(option(
                key.clone(),
                proxy.name.to_string(),
                all || selected.contains(&key),
            ));
        }
    }
    // Active backend snapshots can refer to an older saved configuration. Retain
    // those IDs, without conflating same-named proxies or changing their route.
    let mut observed = BTreeMap::new();
    for snapshot in snapshots {
        if let Action::Proxy(id) = &snapshot.info.action
            && !known.contains(id)
        {
            observed
                .entry(id.clone())
                .or_insert_with(|| snapshot.info.route.clone());
        }
    }
    for (id, label) in observed {
        let key = route_key(&Action::Proxy(id));
        choices.push(option(
            key.clone(),
            format!("{label} (из журнала)"),
            all || selected.contains(&key),
        ));
    }
    for (action, label) in [
        (Action::Direct, "Прямые"),
        (Action::Block, "Заблокированные"),
    ] {
        let key = route_key(&action);
        choices.push(option(
            key.clone(),
            label.into(),
            all || selected.contains(&key),
        ));
    }
    ui.set_connection_route_filters(reconcile(ui.get_connection_route_filters(), choices));

    let statuses = selected_statuses(ui);
    let mut choices = vec![option(
        ALL.into(),
        "Все".into(),
        statuses.len() == STATUSES.len(),
    )];
    choices.extend(STATUSES.iter().map(|status| {
        option(
            status_key(*status),
            status.label().into(),
            statuses.contains(&status_key(*status)),
        )
    }));
    ui.set_connection_status_filters(reconcile(ui.get_connection_status_filters(), choices));
    ui.set_connection_filters_default(is_default(ui));
}

/// Reuse unchanged row models; statistics refreshes must not rebuild checkboxes.
fn reconcile(
    previous: ModelRc<ConnectionFilterRow>,
    choices: Vec<ConnectionFilterOption>,
) -> ModelRc<ConnectionFilterRow> {
    let rows = choices
        .chunks(4)
        .enumerate()
        .map(|(index, chunk)| {
            let values = previous
                .row_data(index)
                .map(|row| row.options)
                .filter(|old| {
                    old.row_count() == chunk.len() && old.iter().zip(chunk).all(|(a, b)| a == *b)
                })
                .unwrap_or_else(|| model(chunk.to_vec()));
            ConnectionFilterRow { options: values }
        })
        .collect::<Vec<_>>();
    if previous.row_count() == rows.len()
        && let Some(model) = previous
            .as_any()
            .downcast_ref::<VecModel<ConnectionFilterRow>>()
    {
        for (index, row) in rows.into_iter().enumerate() {
            if previous.row_data(index).as_ref() != Some(&row) {
                model.set_row_data(index, row);
            }
        }
        previous
    } else {
        model(rows)
    }
}

pub fn toggle_route(ui: &ConnectionsWindow, key: &str, checked: bool) {
    let choices = options(ui.get_connection_route_filters());
    if !choices.iter().any(|choice| choice.key == key) {
        return;
    }
    if key == ALL {
        ui.set_connection_routes_all(checked);
        ui.set_connection_route_selection(routing::strings(vec![]));
        return;
    }
    let available = choices
        .iter()
        .filter(|choice| choice.key != ALL)
        .map(|choice| choice.key.to_string())
        .collect::<HashSet<_>>();
    let mut selected = if ui.get_connection_routes_all() {
        available.clone()
    } else {
        routing::values(ui.get_connection_route_selection())
            .into_iter()
            .collect()
    };
    if checked {
        selected.insert(key.to_string());
    } else {
        selected.remove(key);
    }
    // Keep absent IDs for a later visible journal, but bound selection metadata.
    if selected.len() > MAX_SELECTED_ROUTES {
        selected.retain(|key| available.contains(key));
    }
    let all = available.iter().all(|key| selected.contains(key));
    ui.set_connection_routes_all(all);
    let mut selected = if all {
        vec![]
    } else {
        selected.into_iter().collect::<Vec<_>>()
    };
    selected.sort();
    ui.set_connection_route_selection(routing::strings(selected));
}

pub fn toggle_status(ui: &ConnectionsWindow, key: &str, checked: bool) {
    let mut selected = selected_statuses(ui);
    if key == ALL {
        selected = if checked {
            STATUSES.iter().map(|status| status_key(*status)).collect()
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
    ui.set_connection_status_selection(routing::strings(selected));
}

pub fn reset(ui: &ConnectionsWindow) {
    ui.set_connection_query("".into());
    ui.set_connection_routes_all(true);
    ui.set_connection_route_selection(routing::strings(vec![]));
    ui.set_connection_status_selection(routing::strings(default_statuses()));
}
