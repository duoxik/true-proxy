//! A fallback selection is one validated profile change, with no intermediate proxy.
use super::{State, pending, proxies, report};
use crate::MainWindow;
use anyhow::bail;
use slint::ComponentHandle;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use true_proxy::config::{Action, Config};

pub fn label(config: &Config) -> String {
    match &config.default_action {
        Action::Proxy(_) => format!(
            "Прокси · {}",
            super::route_name(config, &config.default_action)
        ),
        action => super::route_name(config, action),
    }
}

pub fn wire(ui: &MainWindow, state: State, path: PathBuf, statuses: Arc<Mutex<proxies::Statuses>>) {
    let weak = ui.as_weak();
    ui.on_select_fallback(move |kind, proxy_id| {
        if let Some(ui) = weak.upgrade() {
            let result =
                pending::persist(&ui, &state, &path, &statuses.lock().unwrap(), |config| {
                    let action = match kind {
                        0 => Action::Direct,
                        1 => Action::Block,
                        2 => Action::Proxy(config.proxy(&proxy_id)?.id.clone()),
                        _ => bail!("Неизвестный маршрут"),
                    };
                    config.default_action = action;
                    Ok(())
                });
            // The label is refreshed only by a successful save. Failed/busy
            // selections leave both the displayed value and profile untouched.
            report(&ui, result);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};
    use std::{cell::RefCell, rc::Rc};
    use true_proxy::config::Proxy;

    struct Fixture {
        state: State,
        path: PathBuf,
        folder: PathBuf,
    }
    impl Fixture {
        fn new(with_proxies: bool) -> Self {
            let mut config = Config::default();
            if with_proxies {
                config.proxies = [("one", "Первый"), ("two", "Второй")]
                    .into_iter()
                    .map(|(id, name)| Proxy {
                        id: id.into(),
                        name: name.into(),
                        host: "127.0.0.1".into(),
                        port: 1080,
                        username: String::new(),
                        protected_password: None,
                    })
                    .collect();
            }
            let folder =
                std::env::temp_dir().join(format!("true-proxy-fallback-{}", crate::app::id()));
            let path = folder.join("config.json");
            config.save(&path).unwrap();
            Self {
                state: Rc::new(RefCell::new(config)),
                path,
                folder,
            }
        }
        fn window(&self) -> MainWindow {
            i_slint_backend_testing::init_no_event_loop();
            let ui = MainWindow::new().unwrap();
            ui.window().set_size(slint::LogicalSize::new(1120., 780.));
            ui.set_page(1);
            let statuses = Arc::new(Mutex::new(proxies::Statuses::new()));
            crate::app::refresh(&ui, &self.state.borrow(), &statuses.lock().unwrap());
            wire(&ui, self.state.clone(), self.path.clone(), statuses);
            ui.show().unwrap();
            ui
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.path.with_extension("json.tmp"));
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_dir(&self.folder);
        }
    }
    fn button(ui: &MainWindow, label: &str) -> ElementHandle {
        ElementHandle::find_by_accessible_label(ui, label)
            .find(|e| e.accessible_role() == Some(AccessibleRole::Button))
            .unwrap_or_else(|| panic!("Missing button {label}"))
    }
    fn click(ui: &MainWindow, label: &str) {
        button(ui, label).mock_single_click(slint::platform::PointerEventButton::Left);
    }

    #[test]
    fn first_click_and_proxy_hover_save_one_atomic_selection_with_deferred_application() {
        let fixture = Fixture::new(true);
        let ui = fixture.window();
        click(&ui, "Маршрут по умолчанию: Напрямую");
        click(&ui, "Маршрут: Блокировать");
        assert_eq!(
            Config::load(&fixture.path).unwrap().default_action,
            Action::Block
        );
        assert_eq!(ui.get_fallback_label(), "Блокировать");
        assert_eq!(
            ElementHandle::find_by_accessible_label(&ui, "Маршрут: Блокировать")
                .filter(|e| e.accessible_role() == Some(AccessibleRole::Button))
                .count(),
            0,
            "Selection must close the popup"
        );

        let running_snapshot = fixture.state.borrow().clone();
        ui.set_active(true);
        click(&ui, "Маршрут по умолчанию: Блокировать");
        let proxy = button(&ui, "Маршрут: Прокси");
        let position = proxy.absolute_position();
        let size = proxy.size();
        let selector = ElementHandle::find_by_element_id(&ui, "MainWindow::fallback-selector")
            .next()
            .unwrap();
        let popup = ElementHandle::find_by_element_id(&ui, "FallbackSelector::menu-focus")
            .next()
            .unwrap();
        let anchor = selector.absolute_position();
        // The testing API's absolute_position is relative to its popup. Input
        // needs the main-window coordinates of this popup, six pixels above
        // the selector. This is a real hover event, without activating Proxy.
        ui.window()
            .dispatch_event(slint::platform::WindowEvent::PointerMoved {
                position: slint::LogicalPosition::new(
                    anchor.x + position.x + size.width / 2.,
                    anchor.y - popup.size().height - 6. + position.y + size.height / 2.,
                ),
            });
        // No click on Proxy: merely hovering must reveal the configured servers.
        click(&ui, "SOCKS-прокси: Второй");
        assert_eq!(
            Config::load(&fixture.path).unwrap().default_action,
            Action::Proxy("two".into())
        );
        assert_eq!(ui.get_fallback_label(), "Прокси · Второй");
        assert_eq!(running_snapshot.default_action, Action::Block);
        assert!(ui.get_routing_pending() && ui.get_restart_prompt());
        ui.set_restart_prompt(false);
        click(&ui, "Маршрут по умолчанию: Прокси · Второй");
        click(&ui, "Маршрут: Напрямую");
        assert_eq!(
            Config::load(&fixture.path).unwrap().default_action,
            Action::Direct
        );
        assert_eq!(ui.get_fallback_label(), "Напрямую");
    }

    #[test]
    fn no_proxy_choice_is_disabled_and_outside_click_closes_without_saving() {
        let fixture = Fixture::new(false);
        let ui = fixture.window();
        let saved = std::fs::read(&fixture.path).unwrap();
        click(&ui, "Маршрут по умолчанию: Напрямую");
        assert_eq!(
            button(&ui, "Маршрут: Прокси").accessible_enabled(),
            Some(false)
        );
        click(&ui, "Маршрут: Прокси");
        assert_eq!(ui.get_fallback_label(), "Напрямую");
        click(&ui, "+ Создать правило");
        assert_eq!(
            ElementHandle::find_by_accessible_label(&ui, "Маршрут: Прокси")
                .filter(|e| e.accessible_role() == Some(AccessibleRole::Button))
                .count(),
            0
        );
        assert_eq!(std::fs::read(&fixture.path).unwrap(), saved);
    }

    #[test]
    fn busy_and_invalid_proxy_selections_leave_display_and_saved_action_unchanged() {
        let fixture = Fixture::new(true);
        let ui = fixture.window();
        let saved = std::fs::read(&fixture.path).unwrap();
        ui.set_busy(true);
        assert_eq!(
            button(&ui, "Маршрут по умолчанию: Напрямую").accessible_enabled(),
            Some(false)
        );
        click(&ui, "Маршрут по умолчанию: Напрямую");
        assert_eq!(
            ElementHandle::find_by_accessible_label(&ui, "Маршрут: Прокси")
                .filter(|e| e.accessible_role() == Some(AccessibleRole::Button))
                .count(),
            0
        );
        ui.invoke_select_fallback(2, "two".into());
        assert_eq!(ui.get_fallback_label(), "Напрямую");
        assert!(ui.get_notice().contains("Дождитесь"));
        ui.set_busy(false);
        ui.invoke_select_fallback(2, "removed".into());
        assert_eq!(ui.get_fallback_label(), "Напрямую");
        assert!(!ui.get_notice().is_empty());
        assert_eq!(fixture.state.borrow().default_action, Action::Direct);
        assert_eq!(std::fs::read(&fixture.path).unwrap(), saved);
    }
}
