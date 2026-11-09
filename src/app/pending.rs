//! Saved routes stay separate from the running engine until an explicit restart.
use super::{Command, State, proxies, refresh, report};
use crate::MainWindow;
use anyhow::{Context, Result, ensure};
use slint::ComponentHandle;
use std::{path::Path, sync::mpsc::SyncSender};
use true_proxy::config::Config;

fn same_routes(first: &Config, second: &Config) -> bool {
    first.rules == second.rules
        && first.local_networks == second.local_networks
        && first.proxies == second.proxies
        && first.default_action == second.default_action
}

pub fn persist(
    ui: &MainWindow,
    state: &State,
    path: &Path,
    statuses: &proxies::Statuses,
    mutate: impl FnOnce(&mut Config) -> Result<()>,
) -> Result<()> {
    ensure!(
        !ui.get_busy(),
        "Wait for the proxy to finish starting or stopping."
    );
    let mut next = state.borrow().clone();
    mutate(&mut next)?;
    next.validate()?;
    if same_routes(&state.borrow(), &next) {
        ui.set_notice("".into());
        return Ok(());
    }
    next.save(path)?;
    *state.borrow_mut() = next.clone();
    refresh(ui, &next, statuses);
    ui.set_notice("".into());
    ui.set_routing_pending(
        state
            .applied
            .borrow()
            .as_ref()
            .is_some_and(|applied| !same_routes(applied, &next)),
    );
    Ok(())
}

/// Routing edits are blocked from command submission until its acknowledgement.
pub fn acknowledge(ui: &MainWindow, state: &State, active: bool) {
    *state.applied.borrow_mut() = active.then(|| state.borrow().clone());
    ui.set_routing_pending(false);
}

pub fn wire(ui: &MainWindow, state: State, sender: SyncSender<Command>) {
    let weak = ui.as_weak();
    ui.on_restart_routing(move || {
        if let Some(ui) = weak.upgrade() {
            let result = (|| -> Result<()> {
                ensure!(
                    ui.get_active() && !ui.get_busy(),
                    "The proxy is already stopped or restarting."
                );
                // One worker command stops/joins the previous engine before starting
                // the latest saved profile. Saving alone never sends this command.
                sender
                    .try_send(Command::Start(state.borrow().clone()))
                    .context("Could not restart the proxy. Try again.")?;
                ui.set_busy(true);
                Ok(())
            })();
            report(&ui, result);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use i_slint_backend_testing::ElementHandle;
    use std::{path::PathBuf, sync::mpsc};
    use true_proxy::{
        config::{Action, Rule},
        rules::{self, Flow},
    };

    struct Profile {
        state: State,
        path: PathBuf,
    }
    impl Profile {
        fn new() -> Self {
            let folder = std::env::temp_dir().join(format!(
                "true-proxy-pending-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let path = folder.join("config.json");
            let state = super::super::ProfileState::new(Config::default());
            state.borrow().save(&path).unwrap();
            Self { state, path }
        }
        fn save(
            &self,
            ui: &MainWindow,
            mutate: impl FnOnce(&mut Config) -> Result<()>,
        ) -> Result<()> {
            persist(
                ui,
                &self.state,
                &self.path,
                &proxies::Statuses::new(),
                mutate,
            )
        }
    }
    impl Drop for Profile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir(self.path.with_extension("json.tmp"));
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_dir(self.path.parent().unwrap());
        }
    }
    fn window() -> MainWindow {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1120., 780.));
        ui.set_page(1);
        ui.set_active(true);
        ui.show().unwrap();
        ui
    }
    fn click(ui: &MainWindow, label: &str) {
        ElementHandle::find_by_accessible_label(ui, label)
            .next()
            .unwrap()
            .mock_single_click(slint::platform::PointerEventButton::Left);
    }
    fn blocked_rule() -> Rule {
        serde_json::from_value(serde_json::json!({
            "id":"game", "name":"Game", "enabled":true,
            "process_names":["game.exe"], "action":{"kind":"block"}
        }))
        .unwrap()
    }

    #[test]
    fn restart_banner_keeps_running_routes_until_explicit_restart_with_latest_profile() {
        let ui = window();
        let profile = Profile::new();
        acknowledge(&ui, &profile.state, true);
        let running = profile.state.borrow().clone();
        let (sender, commands) = mpsc::sync_channel(1);
        wire(&ui, profile.state.clone(), sender);
        profile
            .save(&ui, |config| {
                config.rules.push(blocked_rule());
                Ok(())
            })
            .unwrap();
        assert_eq!(Config::load(&profile.path).unwrap().rules.len(), 1);
        assert!(ui.get_active() && ui.get_routing_pending());
        assert_eq!(ui.get_dialog(), 0);
        assert!(
            commands.try_recv().is_err(),
            "Saving must not stop or start the engine"
        );
        profile.save(&ui, |_| Ok(())).unwrap();
        assert!(
            ui.get_routing_pending(),
            "Saving identical routes must preserve pending changes"
        );
        profile
            .save(&ui, |config| {
                config.default_action = Action::Block;
                Ok(())
            })
            .unwrap();
        assert!(commands.try_recv().is_err());
        click(&ui, "Restart");
        assert!(ui.get_busy() && ui.get_routing_pending());
        assert_eq!(ui.get_dialog(), 0);
        let Command::Start(latest) = commands.try_recv().unwrap() else {
            panic!("Expected one start command")
        };
        assert_eq!(latest.default_action, Action::Block);
        assert_eq!(latest.rules.len(), 1);
        assert!(latest.routing_enabled);
        for protocol in [
            true_proxy::config::Protocol::Tcp,
            true_proxy::config::Protocol::Udp,
        ] {
            let flow = Flow {
                process_name: "game.exe",
                process_path: "",
                destination: "203.0.113.1:443".parse().unwrap(),
                protocol,
                domains: &[],
            };
            assert_eq!(rules::resolve(&running, &flow), Action::Direct);
            assert_eq!(rules::resolve(&latest, &flow), Action::Block);
            assert_eq!(
                rules::resolve(
                    &latest,
                    &Flow {
                        destination: "203.0.113.1:53".parse().unwrap(),
                        ..flow
                    }
                ),
                Action::Direct
            );
        }
        assert_eq!(
            ElementHandle::find_by_accessible_label(&ui, "Restart")
                .next()
                .unwrap()
                .accessible_enabled(),
            Some(false)
        );
        click(&ui, "Restart");
        assert!(commands.try_recv().is_err());
        assert!(ui.get_routing_pending());
        ui.set_busy(false);
        acknowledge(&ui, &profile.state, true);
        assert!(!ui.get_routing_pending());
        assert_eq!(
            ElementHandle::find_by_accessible_label(&ui, "Restart").count(),
            0
        );
    }

    #[test]
    fn reverting_rule_order_hides_restart_only_when_all_saved_routes_match() {
        let ui = window();
        let profile = Profile::new();
        let mut other = blocked_rule();
        other.id = "apps".into();
        profile
            .save(&ui, |config| {
                config.rules = vec![blocked_rule(), other];
                Ok(())
            })
            .unwrap();
        acknowledge(&ui, &profile.state, true);

        let swap = |config: &mut Config| {
            config.rules.swap(0, 1);
            Ok(())
        };
        profile.save(&ui, swap).unwrap();
        assert!(ui.get_routing_pending());
        profile.save(&ui, swap).unwrap();
        assert!(!ui.get_routing_pending());
        assert_eq!(Config::load(&profile.path).unwrap().rules[0].id, "game");

        profile
            .save(&ui, |config| {
                config.default_action = Action::Block;
                Ok(())
            })
            .unwrap();
        profile.save(&ui, swap).unwrap();
        profile.save(&ui, swap).unwrap();
        assert!(ui.get_routing_pending());
    }

    #[test]
    fn paused_saves_and_rejected_changes_do_not_create_pending_configuration() {
        let ui = window();
        let profile = Profile::new();
        ui.set_active(false);
        profile
            .save(&ui, |config| {
                config.default_action = Action::Block;
                Ok(())
            })
            .unwrap();
        assert!(!ui.get_routing_pending());
        ui.set_active(true);
        ui.set_busy(true);
        assert!(
            profile
                .save(&ui, |config| {
                    config.default_action = Action::Direct;
                    Ok(())
                })
                .is_err()
        );
        ui.set_busy(false);
        assert!(
            profile
                .save(&ui, |config| {
                    config.default_action = Action::Proxy("missing".into());
                    Ok(())
                })
                .is_err()
        );
        std::fs::create_dir(profile.path.with_extension("json.tmp")).unwrap();
        assert!(
            profile
                .save(&ui, |config| {
                    config.default_action = Action::Direct;
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(
            Config::load(&profile.path).unwrap().default_action,
            Action::Block
        );
        assert_eq!(profile.state.borrow().default_action, Action::Block);
        assert!(!ui.get_routing_pending());
    }

    #[test]
    fn full_control_queue_keeps_old_engine_and_pending_notice() {
        let ui = window();
        let profile = Profile::new();
        let (sender, commands) = mpsc::sync_channel(1);
        acknowledge(&ui, &profile.state, true);
        sender.send(Command::Stop).unwrap();
        wire(&ui, profile.state.clone(), sender);
        profile
            .save(&ui, |config| {
                config.default_action = Action::Block;
                Ok(())
            })
            .unwrap();
        click(&ui, "Restart");
        assert!(ui.get_active() && !ui.get_busy() && ui.get_routing_pending());
        assert!(ui.get_notice().contains("Try again"));
        assert!(matches!(commands.try_recv(), Ok(Command::Stop)));
        assert!(commands.try_recv().is_err());
    }
}
