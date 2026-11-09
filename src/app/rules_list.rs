use super::{State, model, pending, proxies, report, route_name};
use crate::{MainWindow, RuleRow};
use anyhow::Result;
use ipnet::IpNet;
use slint::{ComponentHandle, Model};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use true_proxy::{config::Config, editor};

fn network_text(config: &Config) -> String {
    config
        .local_networks
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn refresh(ui: &MainWindow, config: &Config) {
    ui.set_rules(model(
        config
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| RuleRow {
                id: rule.id.clone().into(),
                name: rule.name.clone().into(),
                route: route_name(config, &rule.action).into(),
                enabled: rule.enabled,
                priority: index as i32 + 2,
            })
            .collect(),
    ));
    refresh_table(ui);
}

fn refresh_table(ui: &MainWindow) {
    let query = ui.get_rule_query().trim().to_lowercase();
    let rows = ui
        .get_rules()
        .iter()
        .filter(|row| {
            row.name.to_lowercase().contains(&query) || row.route.to_lowercase().contains(&query)
        })
        .collect();
    ui.set_visible_rules(model(rows));
}

fn parse_networks(input: &str) -> Result<Vec<IpNet>> {
    let mut networks = Vec::new();
    for value in editor::entries(3, input)? {
        let network = value.parse::<IpNet>()?.trunc();
        if !networks.contains(&network) {
            networks.push(network);
        }
    }
    Ok(networks)
}

pub fn wire(ui: &MainWindow, state: State, path: PathBuf, statuses: Arc<Mutex<proxies::Statuses>>) {
    let weak = ui.as_weak();
    ui.on_filter_rules(move || {
        if let Some(ui) = weak.upgrade() {
            refresh_table(&ui);
        }
    });
    let weak = ui.as_weak();
    let saved_state = state.clone();
    ui.on_edit_local_network(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_notice("".into());
            ui.set_local_network_draft(network_text(&saved_state.borrow()).into());
            ui.set_dialog(4);
        }
    });
    let weak = ui.as_weak();
    ui.on_save_local_network(move || {
        if let Some(ui) = weak.upgrade() {
            let result = (|| {
                let networks = parse_networks(&ui.get_local_network_draft())?;
                pending::persist(&ui, &state, &path, &statuses.lock().unwrap(), |config| {
                    config.local_networks = networks;
                    Ok(())
                })?;
                ui.set_dialog(0);
                Ok(())
            })();
            report(&ui, result);
        }
    });
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    use i_slint_backend_testing::ElementHandle;
    use slint::platform::{PointerEventButton, WindowEvent};

    #[test]
    fn rule_search_preserves_priority_and_cidrs_save_with_deferred_apply() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1240., 780.));
        ui.set_page(1);
        let config = Config {
            rules: super::super::preview::sample_rules(),
            proxies: [("preview-local", "Local"), ("preview-backup", "Backup")]
                .into_iter()
                .map(|(id, name)| true_proxy::config::Proxy {
                    id: id.into(),
                    name: name.into(),
                    host: "127.0.0.1".into(),
                    port: 1080,
                    username: String::new(),
                    protected_password: None,
                })
                .collect(),
            ..Config::default()
        };
        let state = super::super::ProfileState::new(config.clone());
        let directory =
            std::env::temp_dir().join(format!("true-proxy-local-editor-{}", super::super::id()));
        let path = directory.join("config.json");
        let statuses = Arc::new(Mutex::new(proxies::Statuses::new()));
        wire(&ui, state.clone(), path.clone(), statuses);
        refresh(&ui, &config);
        ui.show().unwrap();

        let click = |label| {
            ElementHandle::find_by_accessible_label(&ui, label)
                .next()
                .unwrap_or_else(|| panic!("Missing control {label}"))
                .mock_single_click(PointerEventButton::Left);
        };
        assert_eq!(ui.get_visible_rules().row_count(), 2);
        click("Search rules");
        for text in ["g", "A", "m", "E"] {
            ui.window()
                .dispatch_event(WindowEvent::KeyPressed { text: text.into() });
        }
        assert_eq!(ui.get_visible_rules().row_count(), 1);
        assert_eq!(ui.get_visible_rules().row_data(0).unwrap().priority, 3);
        assert_eq!(
            ui.get_visible_rules().row_data(0).unwrap().route,
            "Proxy · Backup"
        );

        click("Edit local network");
        assert_eq!(ui.get_dialog(), 4);
        assert!(ui.get_local_network_draft().contains("192.168.0.0/16"));
        ui.set_local_network_draft("invalid".into());
        click("Save local network");
        assert_eq!(ui.get_dialog(), 4);
        assert!(ui.get_notice().contains("Invalid IP address or CIDR"));
        assert_eq!(state.borrow().local_networks, config.local_networks);
        assert!(!path.exists());

        ui.set_active(true);
        pending::acknowledge(&ui, &state, true);
        ui.set_local_network_draft("192.0.2.15/24\n192.0.2.0/24, fd00::/8".into());
        click("Save local network");
        assert_eq!(ui.get_dialog(), 0);
        assert!(ui.get_routing_pending());
        let saved = Config::load(&path).unwrap();
        assert_eq!(
            saved.local_networks,
            [
                "192.0.2.0/24".parse::<IpNet>().unwrap(),
                "fd00::/8".parse::<IpNet>().unwrap(),
            ]
        );
        assert_eq!(saved.rules, config.rules);
        click("Edit local network");
        assert_eq!(ui.get_local_network_draft(), "192.0.2.0/24\nfd00::/8");
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
