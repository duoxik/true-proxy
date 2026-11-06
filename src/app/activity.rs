use super::{bytes, model, report, routing};
use crate::{ConnectionMonitor, LogRow, MainWindow, ProcessSummary};
use slint::{ComponentHandle, Model, ModelRc, VecModel};
use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    rc::Rc,
    sync::{Arc, atomic::Ordering},
};
use true_proxy::{config::Action, connections::Snapshot, engine::Statistics};

mod filters;

/// Core transfer counters run independently from the visible monitor.
pub fn observable(ui: &MainWindow) -> bool {
    ui.get_page() == 3 && ui.window().is_visible() && !ui.window().is_minimized()
}

pub fn sync_tracking(ui: &MainWindow, statistics: &Statistics) {
    let tracking = observable(ui);
    let was_tracking = statistics.activity.tracking();
    if !tracking && was_tracking {
        statistics.activity.set_tracking(false);
    }
    let finished_statuses = filters::selected_finished_statuses(ui);
    ui.global::<ConnectionMonitor>()
        .set_only_active(finished_statuses.is_empty());
    statistics.activity.set_history_statuses(&finished_statuses);
    if tracking && !was_tracking {
        statistics.activity.set_tracking(true);
    }
}

pub fn suspend_tracking(ui: &MainWindow, statistics: &Statistics) {
    statistics.activity.set_tracking(false);
    clear(ui);
    filters::refresh(ui);
}

fn clear(ui: &MainWindow) {
    let monitor = ui.global::<ConnectionMonitor>();
    if monitor.get_process_summaries().row_count() != 0 {
        monitor.set_process_summaries(model(vec![]));
    }
    monitor.set_connection_event_count(0);
    monitor.set_filtered_event_count(0);
    monitor.set_active_connection_count(0);
    monitor.set_connection_omitted(0);
}

pub fn wire(ui: &MainWindow, statistics: Arc<Statistics>, preferences_path: Option<PathBuf>) {
    if let Some(path) = &preferences_path {
        match filters::Preferences::load(path) {
            Ok(Some(preferences)) => preferences.apply(ui),
            Ok(None) => {}
            Err(error) => report(ui, Err(error.context("Could not load connection filters"))),
        }
    }
    let save = Rc::new(move |ui: &MainWindow| {
        if let Some(path) = &preferences_path
            && let Err(error) = filters::Preferences::save(ui, path)
        {
            report(ui, Err(error));
        }
    });
    let monitor = ui.global::<ConnectionMonitor>();
    let weak = ui.as_weak();
    let stats = statistics.clone();
    monitor.on_filter_connections(move || {
        if let Some(ui) = weak.upgrade() {
            render(&ui, &stats);
        }
    });
    let weak = ui.as_weak();
    let stats = statistics.clone();
    let save_statuses = save.clone();
    monitor.on_set_only_active(move |only_active| {
        if let Some(ui) = weak.upgrade() {
            let selected = if only_active {
                filters::default_statuses()
            } else {
                filters::all_statuses()
            };
            ui.global::<ConnectionMonitor>()
                .set_connection_status_selection(routing::strings(selected));
            render(&ui, &stats);
            save_statuses(&ui);
        }
    });
    let weak = ui.as_weak();
    let stats = statistics.clone();
    let save_routes = save.clone();
    monitor.on_toggle_connection_route(move |key, checked| {
        if let Some(ui) = weak.upgrade() {
            filters::toggle_route(&ui, &key, checked);
            render(&ui, &stats);
            save_routes(&ui);
        }
    });
    let weak = ui.as_weak();
    let stats = statistics.clone();
    let save_statuses = save.clone();
    monitor.on_toggle_connection_status(move |key, checked| {
        if let Some(ui) = weak.upgrade() {
            filters::toggle_status(&ui, &key, checked);
            render(&ui, &stats);
            save_statuses(&ui);
        }
    });
    let weak = ui.as_weak();
    let stats = statistics.clone();
    monitor.on_reset_connection_filters(move || {
        if let Some(ui) = weak.upgrade() {
            filters::reset(&ui);
            render(&ui, &stats);
            save(&ui);
        }
    });
    let weak = ui.as_weak();
    let stats = statistics.clone();
    monitor.on_expand_process(move |name| {
        if let Some(ui) = weak.upgrade() {
            let monitor = ui.global::<ConnectionMonitor>();
            let mut expanded = routing::values(monitor.get_expanded_processes());
            if let Some(index) = expanded
                .iter()
                .position(|old| old.eq_ignore_ascii_case(&name))
            {
                expanded.remove(index);
            } else {
                expanded.push(name.to_string());
            }
            monitor.set_expanded_processes(routing::strings(expanded));
            render(&ui, &stats);
        }
    });
    render(ui, &statistics);
}
pub fn render(ui: &MainWindow, statistics: &Statistics) {
    sync_tracking(ui, statistics);
    filters::refresh(ui);
    if !statistics.activity.tracking() {
        clear(ui);
        return;
    }
    let rows = statistics.activity.snapshots();
    let monitor = ui.global::<ConnectionMonitor>();
    let uploaded = statistics.uploaded.load(Ordering::Relaxed);
    let downloaded = statistics.downloaded.load(Ordering::Relaxed);
    monitor
        .set_active_connection_count(rows.iter().filter(|r| !r.status.finished()).count() as i32);
    monitor.set_total_sent(bytes(uploaded).into());
    monitor.set_total_received(bytes(downloaded).into());
    monitor.set_total_traffic(bytes(uploaded.saturating_add(downloaded)).into());

    let query = monitor.get_connection_query().trim().to_lowercase();
    let all_routes = monitor.get_connection_routes_all();
    let selected_routes = routing::values(monitor.get_connection_route_selection())
        .into_iter()
        .collect::<HashSet<_>>();
    let selected_statuses = filters::selected_statuses(ui);
    let expanded = routing::values(monitor.get_expanded_processes())
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
        if (!query.is_empty() && !key.contains(&query))
            || (!all_routes && !selected_routes.contains(filters::route_key(&row.info.action)))
            || !selected_statuses.contains(&filters::status_key(row.status))
        {
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
                    "Other processes".into()
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
                            pid: format!("PID {}", r.info.pid).into(),
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
                            source: r.info.source.to_string().into(),
                            started: r
                                .timing
                                .and_then(|timing| timing.local_start)
                                .map_or_else(
                                    || "—".into(),
                                    |(hour, minute, second)| {
                                        format!("{hour:02}:{minute:02}:{second:02}")
                                    },
                                )
                                .into(),
                            elapsed: r
                                .timing
                                .map_or_else(
                                    || "—".into(),
                                    |timing| {
                                        if timing.elapsed.as_secs() < 60 {
                                            format!("{:.1}s", timing.elapsed.as_secs_f32())
                                        } else {
                                            super::uptime(timing.elapsed)
                                        }
                                    },
                                )
                                .into(),
                            route: if matches!(r.info.action, Action::Proxy(_)) {
                                format!("Proxy · {}", r.info.route).into()
                            } else {
                                r.info.route.into()
                            },
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
    monitor.set_connection_event_count(rows.len() as i32);
    monitor.set_filtered_event_count(summaries.iter().map(|p| p.events).sum());
    monitor.set_connection_omitted(statistics.activity.omitted().min(i32::MAX as u64) as i32);
    let previous = monitor.get_process_summaries();
    let same_order = previous.row_count() == summaries.len()
        && previous
            .iter()
            .zip(&summaries)
            .all(|(a, b)| a.name == b.name);
    if same_order && let Some(rows) = previous.as_any().downcast_ref::<VecModel<ProcessSummary>>() {
        for (index, mut row) in summaries.into_iter().enumerate() {
            let old = rows.row_data(index).unwrap();
            if update_rows_in_place(&old.connections, &row.connections) {
                row.connections = old.connections.clone();
            }
            if row != old {
                rows.set_row_data(index, row);
            }
        }
    } else {
        monitor.set_process_summaries(model(summaries));
    }
}

fn update_rows_in_place(previous: &ModelRc<LogRow>, next: &ModelRc<LogRow>) -> bool {
    let Some(previous) = previous.as_any().downcast_ref::<VecModel<LogRow>>() else {
        return false;
    };
    if previous.row_count() != next.row_count()
        || previous.iter().zip(next.iter()).any(|(a, b)| a.id != b.id)
    {
        return false;
    }
    for (index, (old, new)) in previous.iter().zip(next.iter()).enumerate() {
        if old != new {
            previous.set_row_data(index, new);
        }
    }
    true
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    use crate::ProxyRow;
    use i_slint_backend_testing::ElementHandle;
    use true_proxy::{
        config::{Action, Protocol},
        connections::{Connection, Info, Status},
    };
    fn window(proxies: &[(&str, &str)]) -> (MainWindow, Arc<Statistics>) {
        i_slint_backend_testing::init_no_event_loop();
        window_with_preferences(proxies, None)
    }
    fn window_with_preferences(
        proxies: &[(&str, &str)],
        preferences: Option<PathBuf>,
    ) -> (MainWindow, Arc<Statistics>) {
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1120., 780.));
        ui.set_page(3);
        ui.set_proxies(model(
            proxies
                .iter()
                .map(|(id, name)| ProxyRow {
                    id: (*id).into(),
                    name: (*name).into(),
                    ..Default::default()
                })
                .collect(),
        ));
        ui.show().unwrap();
        let stats = Arc::new(Statistics::default());
        wire(&ui, stats.clone(), preferences);
        assert!(stats.activity.tracking());
        (ui, stats)
    }
    fn start(
        stats: &Statistics,
        name: &str,
        port: u16,
        action: Action,
        status: Status,
    ) -> Connection {
        let route = match &action {
            Action::Direct => "Direct",
            Action::Block => "Blocked",
            Action::Proxy(_) => "VPN",
        };
        stats
            .activity
            .start(
                Info {
                    pid: 10,
                    process: name.into(),
                    source: format!("192.0.2.1:{port}").parse().unwrap(),
                    destination: "203.0.113.1:443".parse().unwrap(),
                    protocol: Protocol::Tcp,
                    route: route.into(),
                    detail: "Rule".into(),
                    action,
                    stamp: 0,
                },
                status,
            )
            .unwrap()
    }
    fn click(ui: &MainWindow, label: &str, index: usize) {
        ElementHandle::find_by_accessible_label(ui, label)
            .nth(index)
            .unwrap_or_else(|| panic!("Missing control {label} #{index}"))
            .mock_single_click(slint::platform::PointerEventButton::Left);
    }
    fn query(ui: &MainWindow, query: &str) {
        let monitor = ui.global::<ConnectionMonitor>();
        monitor.set_connection_query(query.into());
        monitor.invoke_filter_connections();
    }

    #[test]
    fn process_search_and_route_checkboxes_group_proxies_and_preserve_stable_models() {
        let (ui, stats) = window(&[("p1", "VPN"), ("p2", "VPN")]);
        let monitor = ui.global::<ConnectionMonitor>();
        let _game = start(
            &stats,
            "Game.exe",
            1001,
            Action::Proxy("p1".into()),
            Status::Active,
        );
        let _game2 = start(
            &stats,
            "Game.exe",
            1002,
            Action::Proxy("p2".into()),
            Status::Active,
        );
        let _chat = start(&stats, "chat.exe", 1003, Action::Direct, Status::Connecting);
        stats.uploaded.store(2048, Ordering::Relaxed);
        stats.downloaded.store(4096, Ordering::Relaxed);
        render(&ui, &stats);
        assert_eq!(monitor.get_active_connection_count(), 3);
        assert_eq!(monitor.get_total_sent(), "2.0 KB");
        assert_eq!(monitor.get_total_received(), "4.0 KB");
        assert_eq!(monitor.get_total_traffic(), "6.0 KB");
        let stable = monitor.get_process_summaries();
        let children = stable.row_data(0).unwrap().connections;
        assert_eq!(children.row_data(0).unwrap().route, "Proxy · VPN");
        let route_models = monitor.get_connection_route_filters();
        render(&ui, &stats);
        assert!(stable == monitor.get_process_summaries());
        assert!(
            children
                == monitor
                    .get_process_summaries()
                    .row_data(0)
                    .unwrap()
                    .connections
        );
        assert!(route_models == monitor.get_connection_route_filters());
        assert!(monitor.get_only_active());
        assert_eq!(monitor.get_filtered_event_count(), 2);
        assert_eq!(monitor.get_connection_route_summary(), "Proxy");
        assert_eq!(
            route_models
                .iter()
                .map(|row| (row.label.to_string(), row.checked))
                .collect::<Vec<_>>(),
            [
                ("All".to_owned(), false),
                ("Proxy".to_owned(), true),
                ("Direct".to_owned(), false),
                ("Blocked".to_owned(), false),
            ]
        );
        assert_eq!(
            monitor
                .get_connection_status_filters()
                .iter()
                .filter(|row| row.checked)
                .map(|row| row.label.to_string())
                .collect::<Vec<_>>(),
            ["Connecting", "Active", "Closing"]
        );
        assert_eq!(
            ElementHandle::find_by_accessible_label(&ui, "Only active connections").count(),
            0
        );
        click(&ui, "Connections for Game.exe", 0);
        click(&ui, "Search process name", 0);
        for text in ["g", "A", "m", "E"] {
            ui.window()
                .dispatch_event(slint::platform::WindowEvent::KeyPressed { text: text.into() });
        }
        assert_eq!(monitor.get_filtered_event_count(), 2);
        assert_eq!(monitor.get_active_connection_count(), 3);
        assert!(
            monitor
                .get_process_summaries()
                .row_data(0)
                .unwrap()
                .expanded
        );
        for text in ["203.0.113", "VPN", "Rule", "10"] {
            query(&ui, text);
            assert_eq!(
                monitor.get_filtered_event_count(),
                0,
                "Search must match only process names"
            );
        }
        query(&ui, "");
        click(&ui, "Filter routes", 0);
        click(&ui, "Route: Proxy", 0);
        assert_eq!(monitor.get_filtered_event_count(), 0);
        click(&ui, "Route: Proxy", 0);
        assert_eq!(monitor.get_filtered_event_count(), 2);
        assert_eq!(
            routing::values(monitor.get_connection_route_selection()),
            ["proxy"]
        );
        ui.set_proxies(model(vec![]));
        let _new = start(
            &stats,
            "Game.exe",
            1004,
            Action::Proxy("new".into()),
            Status::Active,
        );
        render(&ui, &stats);
        assert_eq!(
            monitor.get_filtered_event_count(),
            3,
            "Proxy includes every proxied connection regardless of the saved profile"
        );
        query(&ui, "GAME");
        assert!(
            monitor
                .get_process_summaries()
                .row_data(0)
                .unwrap()
                .expanded
        );
        click(&ui, "Route: All", 0);
        assert_eq!(monitor.get_filtered_event_count(), 3);
        click(&ui, "Route: All", 0);
        assert_eq!(monitor.get_filtered_event_count(), 0);
        click(&ui, "Search process name", 0);
        click(&ui, "Reset filters", 0);
        assert_eq!(monitor.get_connection_query(), "");
        assert_eq!(monitor.get_connection_route_summary(), "Proxy");
        assert!(monitor.get_connection_filters_default());
        assert_eq!(monitor.get_filtered_event_count(), 3);
    }

    #[test]
    fn terminal_statuses_start_history_now_and_failed_proxy_is_not_blocked() {
        let (ui, stats) = window(&[("p1", "VPN")]);
        let monitor = ui.global::<ConnectionMonitor>();
        monitor.invoke_set_only_active(true);
        let old = start(&stats, "old.exe", 1000, Action::Direct, Status::Active);
        old.finish(Status::Closed, "");
        let game = start(
            &stats,
            "game.exe",
            1001,
            Action::Proxy("p1".into()),
            Status::Active,
        );
        let direct = start(&stats, "direct.exe", 1002, Action::Direct, Status::Active);
        render(&ui, &stats);
        click(&ui, "Filter statuses", 0);
        click(&ui, "Status: All", 0);
        assert!(!monitor.get_only_active());
        game.finish(Status::Failed, "SOCKS rejected");
        direct.finish(Status::Closed, "");
        let blocked = start(&stats, "block.exe", 1003, Action::Block, Status::Connecting);
        blocked.finish(Status::Blocked, "rule");
        let _active = start(&stats, "active.exe", 1004, Action::Direct, Status::Active);
        render(&ui, &stats);
        assert_eq!(monitor.get_filtered_event_count(), 1);
        click(&ui, "Search process name", 0);
        click(&ui, "Filter routes", 0);
        click(&ui, "Route: Proxy", 0);
        click(&ui, "Route: Blocked", 0);
        assert_eq!(monitor.get_filtered_event_count(), 1);
        assert_eq!(
            monitor.get_process_summaries().row_data(0).unwrap().name,
            "block.exe"
        );
        click(&ui, "Route: Blocked", 0);
        click(&ui, "Route: Proxy", 0);
        assert_eq!(monitor.get_filtered_event_count(), 1);
        assert_eq!(
            monitor.get_process_summaries().row_data(0).unwrap().name,
            "game.exe"
        );
        click(&ui, "Route: All", 0);
        assert_eq!(monitor.get_filtered_event_count(), 4);
        click(&ui, "Search process name", 0);
        click(&ui, "Filter statuses", 0);
        click(&ui, "Status: Connecting", 0);
        assert!(!monitor.get_only_active());
        assert_eq!(
            stats.activity.snapshots().len(),
            4,
            "Changing a nonterminal filter must not clear history"
        );
        click(&ui, "Status: All", 0); // Some unchecked -> select all.
        click(&ui, "Status: All", 0); // All checked -> select none, clear history.
        assert!(monitor.get_only_active());
        assert_eq!(monitor.get_filtered_event_count(), 0);
        assert_eq!(stats.activity.snapshots().len(), 1);
        click(&ui, "Status: Failed", 0);
        assert_eq!(
            monitor.get_filtered_event_count(),
            0,
            "Old history must not return"
        );
        click(&ui, "Status: Active", 0);
        assert_eq!(monitor.get_filtered_event_count(), 1);
    }

    #[test]
    fn selecting_another_finished_status_does_not_backfill_it() {
        let (ui, stats) = window(&[]);
        let monitor = ui.global::<ConnectionMonitor>();
        click(&ui, "Filter statuses", 0);
        click(&ui, "Status: Closed", 0);
        let old = start(
            &stats,
            "old.exe",
            1000,
            Action::Proxy("vpn".into()),
            Status::Connecting,
        );
        old.finish(Status::Failed, "");
        click(&ui, "Status: Failed", 0);
        assert_eq!(monitor.get_filtered_event_count(), 0);
        let fresh = start(
            &stats,
            "fresh.exe",
            1001,
            Action::Proxy("vpn".into()),
            Status::Connecting,
        );
        fresh.finish(Status::Failed, "");
        render(&ui, &stats);
        assert_eq!(monitor.get_filtered_event_count(), 1);
        assert_eq!(
            monitor.get_process_summaries().row_data(0).unwrap().name,
            "fresh.exe"
        );
    }

    #[test]
    fn reopening_keeps_live_connections_and_filters_but_discards_completed_history() {
        let (ui, stats) = window(&[]);
        let monitor = ui.global::<ConnectionMonitor>();
        let game = start(&stats, "game.exe", 1001, Action::Direct, Status::Active);
        let old = start(&stats, "game.exe", 1002, Action::Direct, Status::Active);
        click(&ui, "Filter statuses", 0);
        click(&ui, "Status: Closed", 0);
        click(&ui, "Search process name", 0);
        old.finish(Status::Closed, "");
        let _counter = stats.connection("game.exe");
        stats.uploaded.store(42, Ordering::Relaxed);
        render(&ui, &stats);
        click(&ui, "Filter routes", 0);
        click(&ui, "Route: Proxy", 0);
        click(&ui, "Route: Direct", 0);
        click(&ui, "Search process name", 0);
        click(&ui, "Connections for game.exe", 0);
        click(&ui, "Filter statuses", 0);
        click(&ui, "Status: Failed", 0);
        click(&ui, "Search process name", 0);
        query(&ui, "GAME");
        assert_eq!(monitor.get_filtered_event_count(), 2);

        ui.set_page(0);
        render(&ui, &stats);
        assert!(!stats.activity.tracking());
        assert!(stats.activity.snapshots().is_empty());
        assert_eq!(monitor.get_process_summaries().row_count(), 0);
        assert_eq!(stats.uploaded.load(Ordering::Relaxed), 42);
        assert_eq!(stats.connections.load(Ordering::Relaxed), 1);
        game.finish(Status::Closed, "while hidden");
        let _current = start(&stats, "game.exe", 1003, Action::Direct, Status::Active);

        ui.set_page(3);
        render(&ui, &stats);
        assert!(stats.activity.tracking());
        let rows = stats.activity.snapshots();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, Status::Active);
        assert_eq!(rows[0].info.source.port(), 1003);
        assert_eq!(monitor.get_connection_query(), "GAME");
        assert!(!monitor.get_connection_routes_all());
        assert!(!monitor.get_only_active());
        assert_eq!(monitor.get_filtered_event_count(), 1);
        assert!(
            monitor
                .get_process_summaries()
                .row_data(0)
                .unwrap()
                .expanded
        );

        ui.hide().unwrap();
        render(&ui, &stats);
        assert!(!stats.activity.tracking());
        assert_eq!(monitor.get_process_summaries().row_count(), 0);
        assert!(stats.activity.snapshots().is_empty());
        ui.show().unwrap();
        render(&ui, &stats);
        assert!(stats.activity.tracking());
        assert_eq!(monitor.get_filtered_event_count(), 1);
    }

    #[test]
    fn monitor_keeps_route_filters_compact_even_with_many_configured_proxies() {
        let (ui, stats) = window(&[]);
        let monitor = ui.global::<ConnectionMonitor>();
        ui.set_proxies(model(
            (0..64)
                .map(|index| ProxyRow {
                    id: format!("proxy-{index}").into(),
                    name: format!("Very long proxy connection name number {index}").into(),
                    ..Default::default()
                })
                .collect(),
        ));
        ui.window().set_size(slint::LogicalSize::new(960., 640.));
        render(&ui, &stats);
        assert_eq!(monitor.get_connection_route_filters().row_count(), 4);
        assert_eq!(monitor.get_connection_status_filters().row_count(), 8);
        let list = ElementHandle::find_by_element_id(&ui, "ConnectionsView::connection-list")
            .next()
            .unwrap();
        assert!(
            list.size().height >= 250.,
            "Filters must leave room for connection rows at the minimum window size"
        );
        for label in ["Filter routes", "Filter statuses"] {
            let button = ElementHandle::find_by_accessible_label(&ui, label)
                .next()
                .unwrap();
            let position = button.absolute_position();
            let size = button.size();
            assert!(position.x >= 0. && position.x + size.width <= 960.);
            assert!(position.y >= 0. && position.y + size.height <= 640.);
        }
        assert_eq!(
            ElementHandle::find_by_accessible_label(&ui, "Route: All").count(),
            0
        );
        click(&ui, "Filter routes", 0);
        click(&ui, "Route: Proxy", 0);
        assert!(!monitor.get_connection_routes_all());
        click(&ui, "Route: Blocked", 0);
        assert_eq!(
            routing::values(monitor.get_connection_route_selection()),
            ["block"]
        );

        click(&ui, "Search process name", 0);
        assert_eq!(
            ElementHandle::find_by_accessible_label(&ui, "Route: All").count(),
            0
        );
        click(&ui, "Filter statuses", 0);
        click(&ui, "Status: Failed", 0);
        assert!(!monitor.get_only_active());
        click(&ui, "Search process name", 0);
        assert_eq!(
            ElementHandle::find_by_accessible_label(&ui, "Status: All").count(),
            0
        );
        click(&ui, "Filter statuses", 0);
        assert_eq!(
            ElementHandle::find_by_accessible_label(&ui, "Status: Failed")
                .next()
                .unwrap()
                .accessible_checked(),
            Some(true)
        );
    }

    #[test]
    fn filter_choices_survive_reopening_the_app_and_reset_restores_defaults() {
        i_slint_backend_testing::init_no_event_loop();
        let directory = std::env::temp_dir().join(format!(
            "true-proxy-connection-filters-{}",
            super::super::id()
        ));
        let path = directory.join("connections.json");
        {
            let (ui, _) = window_with_preferences(&[], Some(path.clone()));
            click(&ui, "Filter routes", 0);
            click(&ui, "Route: All", 0);
            click(&ui, "Search process name", 0);
            click(&ui, "Filter statuses", 0);
            click(&ui, "Status: Closed", 0);
            click(&ui, "Status: Active", 0);
        }
        {
            let (ui, _) = window_with_preferences(&[], Some(path.clone()));
            let monitor = ui.global::<ConnectionMonitor>();
            assert!(monitor.get_connection_routes_all());
            assert_eq!(
                routing::values(monitor.get_connection_status_selection()),
                ["0", "2", "3"]
            );
            query(&ui, "browser");
            click(&ui, "Reset filters", 0);
            assert_eq!(monitor.get_connection_query(), "");
            assert!(monitor.get_connection_filters_default());
        }
        let (ui, _) = window_with_preferences(&[], Some(path.clone()));
        let monitor = ui.global::<ConnectionMonitor>();
        assert!(monitor.get_connection_filters_default());
        assert_eq!(monitor.get_connection_route_summary(), "Proxy");
        assert_eq!(
            routing::values(monitor.get_connection_status_selection()),
            filters::default_statuses()
        );
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
