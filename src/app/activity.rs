use super::{bytes, model, routing};
use crate::{LogRow, MainWindow, ProcessSummary};
use slint::{ComponentHandle, Model, VecModel};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::Arc,
};
use true_proxy::{connections::Snapshot, engine::Statistics};

pub fn wire(ui: &MainWindow, statistics: Arc<Statistics>) {
    let weak = ui.as_weak();
    let stats = statistics.clone();
    ui.on_filter_connections(move || {
        if let Some(ui) = weak.upgrade() {
            render(&ui, &stats);
        }
    });
    let weak = ui.as_weak();
    let stats = statistics.clone();
    ui.on_set_only_active(move |only_active| {
        stats.activity.set_only_active(only_active);
        if let Some(ui) = weak.upgrade() {
            render(&ui, &stats);
        }
    });
    let weak = ui.as_weak();
    ui.on_expand_process(move |name| {
        if let Some(ui) = weak.upgrade() {
            let mut expanded = routing::values(ui.get_expanded_processes());
            if let Some(index) = expanded
                .iter()
                .position(|old| old.eq_ignore_ascii_case(&name))
            {
                expanded.remove(index);
            } else {
                expanded.push(name.to_string());
            }
            ui.set_expanded_processes(routing::strings(expanded));
            render(&ui, &statistics);
        }
    });
}
fn matches_query(row: &Snapshot, query: &str) -> bool {
    query.is_empty()
        || [
            row.info.process.clone(),
            row.info.source.to_string(),
            row.info.destination.to_string(),
            row.info.route.clone(),
            row.info.detail.clone(),
            row.status.label().into(),
            row.info.pid.to_string(),
        ]
        .iter()
        .any(|value| value.to_lowercase().contains(query))
}
pub fn render(ui: &MainWindow, statistics: &Statistics) {
    let selected = ui
        .get_connection_processes()
        .row_data(ui.get_connection_process().max(0) as usize)
        .map(|s| s.to_string())
        .filter(|_| ui.get_connection_process() > 0);
    let rows = statistics
        .activity
        .snapshots()
        .into_iter()
        .filter(|r| !ui.get_only_active() || !r.status.finished())
        .collect::<Vec<_>>();
    let mut names = BTreeSet::new();
    for row in &rows {
        names.insert(row.info.process.clone());
    }
    // Keep an explicitly selected app while it has no active connections;
    // otherwise a close event silently switches the user's filter to all apps.
    if let Some(selected) = &selected
        && !names.iter().any(|name| name.eq_ignore_ascii_case(selected))
    {
        names.insert(selected.clone());
    }
    let names = std::iter::once("Все процессы".into())
        .chain(names)
        .collect::<Vec<String>>();
    let index = selected
        .as_ref()
        .and_then(|s| names.iter().position(|name| name.eq_ignore_ascii_case(s)))
        .unwrap_or(0);
    let selected = (index > 0).then(|| names[index].to_lowercase());
    if routing::values(ui.get_connection_processes()) != names {
        ui.set_connection_processes(routing::strings(names));
    }
    ui.set_connection_process(index as i32);
    let query = ui.get_connection_query().to_lowercase();
    let expanded = routing::values(ui.get_expanded_processes())
        .into_iter()
        .map(|s| s.to_lowercase())
        .collect::<HashSet<_>>();
    let counters = statistics
        .process_snapshots()
        .into_iter()
        .map(|p| (p.name.to_lowercase(), p))
        .collect::<BTreeMap<_, _>>();
    let mut groups = BTreeMap::<String, Vec<Snapshot>>::new();
    for row in &rows {
        let mut key = row.info.process.to_lowercase();
        if selected.as_ref().is_some_and(|name| name != &key) || !matches_query(row, &query) {
            continue;
        }
        if groups.len() >= 511 && !groups.contains_key(&key) {
            key = "\0other".into();
        }
        groups.entry(key).or_default().push(row.clone());
    }
    let mut summaries = groups
        .into_iter()
        .map(|(key, rows)| {
            let active = rows.iter().filter(|r| !r.status.finished()).count();
            let counters = counters.get(&key);
            ProcessSummary {
                name: if key == "\0other" {
                    "Другие процессы".into()
                } else {
                    rows[0].info.process.clone().into()
                },
                active: active as i32,
                events: rows.len() as i32,
                expanded: expanded.contains(&key),
                uploaded: bytes(counters.map_or(0, |p| p.uploaded)).into(),
                downloaded: bytes(counters.map_or(0, |p| p.downloaded)).into(),
                connections: model(
                    rows.into_iter()
                        .map(|r| LogRow {
                            id: r.id.to_string().into(),
                            process: r.info.process.into(),
                            destination: format!(
                                "{} · {}",
                                if r.info.protocol == true_proxy::config::Protocol::Tcp {
                                    "TCP"
                                } else {
                                    "UDP"
                                },
                                r.info.destination
                            )
                            .into(),
                            source: format!("{} · PID {}", r.info.source, r.info.pid).into(),
                            route: r.info.route.into(),
                            message: r.info.detail.into(),
                            status: r.status.label().into(),
                            state: r.status as i32,
                        })
                        .collect(),
                ),
            }
        })
        .collect::<Vec<_>>();
    summaries.sort_by(|a, b| {
        b.active
            .cmp(&a.active)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    ui.set_connection_event_count(rows.len() as i32);
    ui.set_filtered_event_count(summaries.iter().map(|p| p.events).sum());
    ui.set_connection_omitted(statistics.activity.omitted().min(i32::MAX as u64) as i32);
    let previous = ui.get_process_summaries();
    let same_order = previous.row_count() == summaries.len()
        && previous
            .iter()
            .zip(&summaries)
            .all(|(a, b)| a.name == b.name);
    if same_order && let Some(rows) = previous.as_any().downcast_ref::<VecModel<ProcessSummary>>() {
        for (index, mut row) in summaries.into_iter().enumerate() {
            let old = rows.row_data(index).unwrap();
            if old.connections.row_count() == row.connections.row_count()
                && old
                    .connections
                    .iter()
                    .zip(row.connections.iter())
                    .all(|(a, b)| a.id == b.id && a.state == b.state)
            {
                row.connections = old.connections.clone();
            }
            if row != old {
                rows.set_row_data(index, row);
            }
        }
    } else {
        ui.set_process_summaries(model(summaries));
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    use true_proxy::{
        config::Protocol,
        connections::{Connection, Info, Status},
    };
    fn start(stats: &Statistics, name: &str, port: u16) -> Connection {
        stats
            .activity
            .start(
                Info {
                    pid: 10,
                    process: name.into(),
                    source: format!("192.0.2.1:{port}").parse().unwrap(),
                    destination: "203.0.113.1:443".parse().unwrap(),
                    protocol: Protocol::Tcp,
                    route: "VPN".into(),
                    detail: "Rule".into(),
                    proxied: true,
                    stamp: 0,
                },
                Status::Active,
            )
            .unwrap()
    }
    #[test]
    fn active_default_history_toggle_filters_and_accordion_use_connection_lifetimes() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1120., 780.));
        ui.set_page(3);
        ui.show().unwrap();
        let stats = Arc::new(Statistics::default());
        wire(&ui, stats.clone());
        let old = start(&stats, "old.exe", 1000);
        old.finish(Status::Closed, "");
        let game = start(&stats, "game.exe", 1001);
        let chat = start(&stats, "chat.exe", 1002);
        render(&ui, &stats);
        let stable = ui.get_process_summaries();
        let children = stable.row_data(0).unwrap().connections;
        render(&ui, &stats);
        assert!(stable == ui.get_process_summaries());
        assert!(children == ui.get_process_summaries().row_data(0).unwrap().connections);
        assert!(ui.get_only_active());
        assert_eq!(ui.get_filtered_event_count(), 2);
        i_slint_backend_testing::ElementHandle::find_by_accessible_label(
            &ui,
            "Подключения game.exe",
        )
        .next()
        .unwrap()
        .mock_single_click(slint::platform::PointerEventButton::Left);
        assert!(
            ui.get_process_summaries()
                .iter()
                .find(|r| r.name == "game.exe")
                .unwrap()
                .expanded
        );
        let checkbox = || {
            i_slint_backend_testing::ElementHandle::find_by_accessible_label(
                &ui,
                "Только активные соединения",
            )
            .next()
            .unwrap()
        };
        checkbox().mock_single_click(slint::platform::PointerEventButton::Left);
        assert!(!ui.get_only_active());
        game.finish(Status::Closed, "");
        render(&ui, &stats);
        assert_eq!(ui.get_filtered_event_count(), 2);
        assert!(
            ui.get_process_summaries()
                .iter()
                .any(|r| r.name == "game.exe"
                    && r.active == 0
                    && r.connections.row_data(0).unwrap().status == "Завершено"
                    && r.expanded)
        );
        ui.set_connection_query("game.exe".into());
        ui.invoke_filter_connections();
        assert_eq!(ui.get_filtered_event_count(), 1);
        ui.set_connection_query("".into());
        checkbox().mock_single_click(slint::platform::PointerEventButton::Left);
        assert!(ui.get_only_active());
        assert_eq!(ui.get_filtered_event_count(), 1);
        checkbox().mock_single_click(slint::platform::PointerEventButton::Left);
        assert_eq!(
            ui.get_filtered_event_count(),
            1,
            "Old completions must not return"
        );
        chat.finish(Status::Failed, "error");
        render(&ui, &stats);
        assert_eq!(ui.get_filtered_event_count(), 1);
        ui.set_connection_process(1);
        checkbox().mock_single_click(slint::platform::PointerEventButton::Left);
        assert_eq!(ui.get_process_summaries().row_count(), 0);
        assert!(
            ui.get_connection_process() > 0,
            "A selected process must not reset when its last connection finishes"
        );
    }
}
