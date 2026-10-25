//! Saved routes stay separate from the running engine until an explicit restart.
use super::{Command, State, proxies, refresh, report};
use crate::MainWindow;
use anyhow::{Context, Result, ensure};
use slint::ComponentHandle;
use std::{path::Path, sync::mpsc::SyncSender};
use true_proxy::config::Config;

pub fn persist(
    ui: &MainWindow,
    state: &State,
    path: &Path,
    statuses: &proxies::Statuses,
    mutate: impl FnOnce(&mut Config) -> Result<()>,
) -> Result<()> {
    ensure!(
        !ui.get_busy(),
        "Дождитесь завершения запуска или остановки прокси."
    );
    let mut next = state.borrow().clone();
    mutate(&mut next)?;
    next.validate()?;
    let changed = {
        let previous = state.borrow();
        previous.rules != next.rules
            || previous.proxies != next.proxies
            || previous.default_action != next.default_action
    };
    if !changed {
        ui.set_notice("".into());
        return Ok(());
    }
    next.save(path)?;
    *state.borrow_mut() = next.clone();
    refresh(ui, &next, statuses);
    ui.set_notice("".into());
    ui.set_routing_pending(ui.get_active());
    ui.set_restart_prompt(ui.get_active());
    Ok(())
}

/// Only a completed lifecycle acknowledgement clears the pending changes.
pub fn on_status(ui: &MainWindow, busy: bool) {
    if !busy {
        ui.set_routing_pending(false);
        ui.set_restart_prompt(false);
    }
}

pub fn wire(ui: &MainWindow, state: State, sender: SyncSender<Command>) {
    let weak = ui.as_weak();
    ui.on_restart_routing(move || {
        if let Some(ui) = weak.upgrade() {
            let result = (|| -> Result<()> {
                ensure!(
                    ui.get_active() && !ui.get_busy(),
                    "Прокси уже остановлен или перезапускается."
                );
                // One worker command stops/joins the previous engine before starting
                // the latest saved profile. Saving alone never sends this command.
                sender
                    .try_send(Command::Start(state.borrow().clone()))
                    .context("Не удалось перезапустить прокси. Повторите действие.")?;
                ui.set_busy(true);
                Ok(())
            })();
            ui.set_restart_prompt(false);
            report(&ui, result);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use i_slint_backend_testing::ElementHandle;
    use std::{cell::RefCell, path::PathBuf, rc::Rc, sync::mpsc};
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
            let state = Rc::new(RefCell::new(Config::default()));
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
    fn save_later_keeps_running_routes_until_explicit_restart_with_latest_profile() {
        let ui = window();
        let profile = Profile::new();
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
        assert!(ui.get_active() && ui.get_routing_pending() && ui.get_restart_prompt());
        assert!(
            commands.try_recv().is_err(),
            "Saving must not stop or start the engine"
        );
        click(&ui, "Применить позже");
        assert!(!ui.get_restart_prompt() && ui.get_routing_pending() && ui.get_active());
        assert!(commands.try_recv().is_err());
        profile.save(&ui, |_| Ok(())).unwrap();
        assert!(
            !ui.get_restart_prompt(),
            "Saving identical routes must not re-prompt"
        );
        profile
            .save(&ui, |config| {
                config.default_action = Action::Block;
                Ok(())
            })
            .unwrap();
        click(&ui, "Применить позже");
        click(&ui, "Перезапустить…");
        assert!(ui.get_restart_prompt());
        click(&ui, "Перезапустить прокси");
        assert!(ui.get_busy() && ui.get_routing_pending() && !ui.get_restart_prompt());
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
        // The banner is hidden during a restart, so no second request can be sent.
        assert_eq!(
            ElementHandle::find_by_accessible_label(&ui, "Перезапустить…").count(),
            0
        );
        assert!(commands.try_recv().is_err());
        on_status(&ui, true);
        assert!(ui.get_routing_pending());
        ui.set_busy(false);
        on_status(&ui, false);
        assert!(!ui.get_routing_pending());
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
        assert!(!ui.get_routing_pending() && !ui.get_restart_prompt());
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
        assert!(!ui.get_routing_pending() && !ui.get_restart_prompt());
    }

    #[test]
    fn full_control_queue_keeps_old_engine_and_pending_notice() {
        let ui = window();
        let profile = Profile::new();
        let (sender, commands) = mpsc::sync_channel(1);
        sender.send(Command::Stop).unwrap();
        wire(&ui, profile.state.clone(), sender);
        profile
            .save(&ui, |config| {
                config.default_action = Action::Block;
                Ok(())
            })
            .unwrap();
        click(&ui, "Перезапустить прокси");
        assert!(ui.get_active() && !ui.get_busy() && ui.get_routing_pending());
        assert!(!ui.get_restart_prompt());
        assert!(ui.get_notice().contains("Повторите"));
        assert!(matches!(commands.try_recv(), Ok(Command::Stop)));
        assert!(commands.try_recv().is_err());
    }
}
