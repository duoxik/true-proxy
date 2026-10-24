use super::{bytes, model, routing};
use crate::{LogRow, MainWindow, ProcessSummary};
use slint::{ComponentHandle, Model};
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};
use true_proxy::engine::{LogEntry, ProcessSnapshot, Statistics};

pub fn wire(ui: &MainWindow, statistics: Arc<Statistics>) {
    let weak = ui.as_weak();
    let stats = statistics.clone();
    ui.on_filter_connections(move || {
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

fn matches_query(event: &LogEntry, query: &str) -> bool {
    query.is_empty()
        || [
            &event.process,
            &event.destination,
            &event.route,
            &event.message,
        ]
        .iter()
        .any(|value| value.to_lowercase().contains(query))
}

pub fn render(ui: &MainWindow, statistics: &Statistics) {
    let selected = if ui.get_connection_process() > 0 {
        ui.get_connection_processes()
            .row_data(ui.get_connection_process() as usize)
            .map(|name| name.to_string())
    } else {
        None
    };
    let logs = statistics.logs();
    let mut grouped = BTreeMap::<String, (ProcessSnapshot, Vec<LogEntry>)>::new();
    for process in statistics.process_snapshots() {
        grouped.insert(process.name.to_lowercase(), (process, vec![]));
    }
    for event in &logs {
        grouped
            .entry(event.process.to_lowercase())
            .or_insert_with(|| {
                (
                    ProcessSnapshot {
                        name: event.process.clone(),
                        active: 0,
                        uploaded: 0,
                        downloaded: 0,
                    },
                    vec![],
                )
            })
            .1
            .push(event.clone());
    }
    let names = std::iter::once("Все процессы".to_string())
        .chain(grouped.values().map(|(process, _)| process.name.clone()))
        .collect::<Vec<_>>();
    let index = selected
        .as_ref()
        .and_then(|selected| {
            names
                .iter()
                .position(|name| name.eq_ignore_ascii_case(selected))
        })
        .unwrap_or(0);
    let selected = if index == 0 {
        None
    } else {
        Some(names[index].to_lowercase())
    };
    ui.set_connection_processes(routing::strings(names));
    ui.set_connection_process(index as i32);
    let expanded = routing::values(ui.get_expanded_processes())
        .into_iter()
        .map(|name| name.to_lowercase())
        .filter(|name| grouped.contains_key(name))
        .collect::<HashSet<_>>();
    ui.set_expanded_processes(routing::strings(expanded.iter().cloned().collect()));
    let query = ui.get_connection_query().to_lowercase();
    let mut summaries = grouped
        .into_values()
        .filter_map(|(process, events)| {
            let key = process.name.to_lowercase();
            if selected.as_ref().is_some_and(|name| *name != key) {
                return None;
            }
            let events = events
                .into_iter()
                .filter(|event| matches_query(event, &query))
                .collect::<Vec<_>>();
            if !query.is_empty() && !key.contains(&query) && events.is_empty() {
                return None;
            }
            Some((process, events))
        })
        .collect::<Vec<_>>();
    summaries.sort_by(|(a, _), (b, _)| {
        b.active
            .cmp(&a.active)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    ui.set_connection_event_count(logs.len() as i32);
    ui.set_filtered_event_count(
        summaries
            .iter()
            .map(|(_, events)| events.len())
            .sum::<usize>() as i32,
    );
    ui.set_process_summaries(model(
        summaries
            .into_iter()
            .map(|(process, events)| ProcessSummary {
                expanded: expanded.contains(&process.name.to_lowercase()),
                name: process.name.into(),
                active: process.active.min(i32::MAX as u64) as i32,
                events: events.len() as i32,
                uploaded: bytes(process.uploaded).into(),
                downloaded: bytes(process.downloaded).into(),
                connections: model(
                    events
                        .into_iter()
                        .map(|event| LogRow {
                            process: event.process.into(),
                            destination: event.destination.into(),
                            route: event.route.into(),
                            message: event.message.into(),
                        })
                        .collect(),
                ),
            })
            .collect(),
    ));
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    #[test]
    fn accordion_filters_and_expansion_survive_refresh_and_log_clear() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1120., 780.));
        ui.set_page(3);
        ui.show().unwrap();
        let stats = Arc::new(Statistics::default());
        wire(&ui, stats.clone());
        let _active = stats.connection("game.exe");
        stats.log("game.exe", "1.2.3.4:443", "VPN", "TCP");
        stats.log("GAME.exe", "1.2.3.5:80", "VPN", "TCP");
        stats.log("chat.exe", "2.3.4.5:443", "Direct", "TCP");
        render(&ui, &stats);
        assert_eq!(ui.get_filtered_event_count(), 3);
        assert_eq!(ui.get_process_summaries().row_data(0).unwrap().active, 1);
        let header = i_slint_backend_testing::ElementHandle::find_by_accessible_label(
            &ui,
            "Подключения game.exe",
        )
        .next()
        .unwrap();
        header.mock_single_click(slint::platform::PointerEventButton::Left);
        assert!(
            ui.get_process_summaries().row_data(0).unwrap().expanded,
            "First click must expand"
        );
        assert_eq!(
            ui.get_process_summaries()
                .row_data(0)
                .unwrap()
                .connections
                .row_count(),
            2
        );
        render(&ui, &stats);
        assert!(ui.get_process_summaries().row_data(0).unwrap().expanded);
        ui.set_connection_process(2);
        ui.invoke_filter_connections();
        assert_eq!(ui.get_process_summaries().row_count(), 1);
        assert_eq!(ui.get_filtered_event_count(), 2);
        ui.set_connection_query("1.2.3.5".into());
        ui.invoke_filter_connections();
        assert_eq!(ui.get_filtered_event_count(), 1);
        ui.set_connection_query("".into());
        stats.clear();
        render(&ui, &stats);
        let row = ui.get_process_summaries().row_data(0).unwrap();
        assert_eq!(row.connections.row_count(), 0);
        assert_eq!(row.active, 1);
        assert!(row.expanded);
        i_slint_backend_testing::ElementHandle::find_by_accessible_label(
            &ui,
            "Подключения game.exe",
        )
        .next()
        .unwrap()
        .mock_single_click(slint::platform::PointerEventButton::Left);
        assert!(
            !ui.get_process_summaries().row_data(0).unwrap().expanded,
            "A second click must collapse"
        );
    }
}
