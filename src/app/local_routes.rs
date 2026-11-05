//! A local-network route is an ordinary user-confirmed rule, saved at highest priority.
use super::{reset_rule, routing};
use crate::MainWindow;
use slint::ComponentHandle;
use true_proxy::config::{Config, Rule};

fn open(ui: &MainWindow) {
    reset_rule(ui);
    let preset = Rule::local_network(String::new());
    ui.set_form_name(preset.name.into());
    ui.set_form_action(1);
    ui.set_form_networks(routing::strings(
        preset.networks.iter().map(ToString::to_string).collect(),
    ));
    ui.set_form_advanced(true);
    ui.set_form_prepend_rule(true);
    ui.set_dialog(2);
}

pub fn wire(ui: &MainWindow) {
    let weak = ui.as_weak();
    ui.on_add_local_rule(move || {
        if let Some(ui) = weak.upgrade() {
            open(&ui);
        }
    });
}

pub fn put(config: &mut Config, rule: Rule, prepend: bool) {
    if let Some(old) = config.rules.iter_mut().find(|old| old.id == rule.id) {
        *old = rule;
    } else if prepend {
        config.rules.insert(0, rule);
    } else {
        config.rules.push(rule);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{pending, proxies};
    use slint::Model;
    use std::{cell::RefCell, rc::Rc};
    use true_proxy::{
        config::{Action, Protocol},
        rules::{self, Flow},
    };

    #[test]
    fn opening_preset_clears_stale_selectors_and_cancel_does_not_create_a_rule() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        wire(&ui);
        ui.set_form_id("previous".into());
        ui.set_form_processes(routing::strings(vec!["game.exe".into()]));
        ui.set_form_new_port("443".into());
        ui.set_form_enabled(false);
        ui.invoke_add_local_rule();
        assert_eq!(ui.get_dialog(), 2);
        assert_eq!(ui.get_form_name(), "Локальная сеть");
        assert!(ui.get_form_id().is_empty());
        assert!(routing::values(ui.get_form_processes()).is_empty());
        assert!(ui.get_form_new_port().is_empty());
        assert!(ui.get_form_enabled() && ui.get_form_advanced() && ui.get_form_prepend_rule());
        assert_eq!(ui.get_form_action(), 1);
        assert_eq!(routing::values(ui.get_form_networks()).len(), 6);
        assert_eq!(
            ui.get_rules().row_count(),
            0,
            "Opening must not save anything"
        );
        ui.set_dialog(0);
        reset_rule(&ui);
        assert!(
            !ui.get_form_prepend_rule(),
            "A later ordinary rule must append"
        );
        assert!(routing::values(ui.get_form_networks()).is_empty());
    }

    #[test]
    fn saved_preset_precedes_app_rule_and_later_edits_keep_position_and_pending_snapshot() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.set_active(true);
        let block: Rule = serde_json::from_value(serde_json::json!({
            "id":"app", "name":"App", "enabled":true,
            "process_names":["game.exe"], "action":{"kind":"block"}
        }))
        .unwrap();
        let state = Rc::new(RefCell::new(Config {
            rules: vec![block],
            ..Config::default()
        }));
        let running = state.borrow().clone();
        let folder =
            std::env::temp_dir().join(format!("true-proxy-local-route-{}", crate::app::id()));
        let path = folder.join("config.json");
        state.borrow().save(&path).unwrap();
        let flow = Flow {
            process_name: "game.exe",
            process_path: "",
            destination: "192.168.50.1:445".parse().unwrap(),
            protocol: Protocol::Tcp,
            domains: &[],
        };
        open(&ui);
        pending::persist(&ui, &state, &path, &proxies::Statuses::new(), |config| {
            put(
                config,
                Rule::local_network("local".into()),
                ui.get_form_prepend_rule(),
            );
            Ok(())
        })
        .unwrap();
        assert_eq!(rules::resolve(&running, &flow), Action::Block);
        let saved = Config::load(&path).unwrap();
        assert_eq!(saved.rules[0].id, "local");
        assert_eq!(rules::resolve(&saved, &flow), Action::Direct);
        assert!(ui.get_routing_pending() && ui.get_restart_prompt());

        let mut edited = saved.rules[0].clone();
        edited.enabled = false;
        edited.networks = vec!["192.168.50.0/24".parse().unwrap()];
        pending::persist(&ui, &state, &path, &proxies::Statuses::new(), |config| {
            put(config, edited, false);
            Ok(())
        })
        .unwrap();
        let saved = Config::load(&path).unwrap();
        assert_eq!(saved.rules[0].id, "local");
        assert_eq!(saved.rules.len(), 2);
        assert_eq!(saved.rules[0].networks.len(), 1);
        assert_eq!(rules::resolve(&saved, &flow), Action::Block);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(folder).unwrap();
    }
}
