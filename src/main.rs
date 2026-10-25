#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod app;

slint::include_modules!();

fn main() {
    // Integration-only parent: never shipped and never opens UI, UAC or WinDivert.
    #[cfg(all(windows, debug_assertions))]
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "--exercise-update")
    {
        let result = (|| -> anyhow::Result<()> {
            let directory = std::path::PathBuf::from(
                std::env::args_os()
                    .nth(2)
                    .ok_or_else(|| anyhow::anyhow!("Missing fixture directory"))?,
            );
            let payload = directory.join("payload.exe");
            let staged = true_proxy::updates::Staged {
                directory,
                release: true_proxy::updates::Release {
                    version: "999.0.0".into(),
                    asset_id: 1,
                    size: std::fs::metadata(&payload)?.len(),
                    sha256: true_proxy::platform::windows::update::sha256(&payload)?,
                },
            };
            true_proxy::updates::installer::prepare(&staged)
        })();
        if let Err(error) = &result
            && let Some(root) = std::env::args_os().nth(2)
        {
            let _ = std::fs::write(
                std::path::PathBuf::from(root).join("parent-error.txt"),
                format!("{error:#}"),
            );
        }
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }
    #[cfg(windows)]
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "--apply-update")
    {
        let arguments = std::env::args().skip(2).collect::<Vec<_>>();
        if arguments.len() != 3 {
            std::process::exit(2);
        }
        let result = (|| -> anyhow::Result<()> {
            true_proxy::updates::installer::apply(
                arguments[0].parse()?,
                arguments[1].parse()?,
                &arguments[2],
            )
        })();
        if let Err(error) = &result {
            let parent_running = arguments[0]
                .parse()
                .ok()
                .zip(arguments[1].parse().ok())
                .and_then(|(pid, created)| {
                    true_proxy::platform::windows::update::Parent::open(pid, created).ok()
                })
                .is_some_and(|parent| parent.is_running());
            if !parent_running {
                true_proxy::platform::show_error(&format!(
                    "Не удалось установить обновление: {error:#}"
                ));
            }
        }
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }
    #[cfg(windows)]
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "--check-updates" || arg == "--download-update")
    {
        let arguments = std::env::args_os().collect::<Vec<_>>();
        let Some(report) = arguments.get(2) else {
            std::process::exit(2);
        };
        let result = (|| -> anyhow::Result<serde_json::Value> {
            let release = true_proxy::updates::latest()?;
            let current = arguments
                .get(3)
                .and_then(|arg| arg.to_str())
                .unwrap_or(true_proxy::updates::VERSION);
            let available = release
                .as_ref()
                .map(|release| true_proxy::updates::is_newer(release, current))
                .transpose()?
                .unwrap_or(false);
            if arguments[1] == "--download-update" {
                let root = std::path::Path::new(report)
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("Missing output directory"))?;
                let release = release
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("No published executable"))?;
                let staged =
                    true_proxy::updates::download(release, &root.join("download"), |_, _| {})?;
                return Ok(
                    serde_json::json!({"ok":true,"download":staged.payload(),"release":release,"interception":false,"installation":false}),
                );
            }
            Ok(
                serde_json::json!({"ok":true,"current_version":current,"available":available,"release":release,"interception":false,"installation":false}),
            )
        })();
        let data = match &result {
            Ok(data) => data.clone(),
            Err(error) => {
                serde_json::json!({"ok":false,"error":format!("{error:#}"),"interception":false,"installation":false})
            }
        };
        let written = std::fs::write(report, data.to_string());
        std::process::exit(if result.is_ok() && written.is_ok() {
            0
        } else {
            1
        });
    }
    // Safe packaging diagnostic: no UI, config, elevation, or WinDivertOpen.
    #[cfg(windows)]
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "--check-driver")
    {
        let Some(report) = std::env::args_os().nth(2) else {
            std::process::exit(2);
        };
        let result = (|| -> anyhow::Result<std::path::PathBuf> {
            let driver = true_proxy::platform::windows::divert::Driver::load()?;
            driver.validate_filter("!impostor and !loopback and ((outbound and (tcp or udp)) or (inbound and (tcp.SrcPort == 53 or udp.SrcPort == 53)))", 0)?;
            driver.validate_filter("event == CLOSE and protocol == 17", 3)?;
            Ok(driver.library_path().to_owned())
        })();
        let report_data = match &result {
            Ok(path) => serde_json::json!({"ok": true, "dll": path, "interception": false}),
            Err(error) => {
                serde_json::json!({"ok": false, "error": format!("{error:#}"), "interception": false})
            }
        };
        let written = std::fs::write(report, report_data.to_string());
        std::process::exit(if result.is_ok() && written.is_ok() {
            0
        } else {
            1
        });
    }
    if let Err(error) = app::run() {
        true_proxy::platform::show_error(&format!("{error:#}"));
    }
}

#[cfg(all(test, debug_assertions))]
mod ui_tests {
    use super::*;
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};
    use slint::{ComponentHandle, platform::PointerEventButton};
    use std::{cell::Cell, rc::Rc};

    fn click(ui: &MainWindow, label: &str) {
        let element = ElementHandle::find_by_accessible_label(ui, label)
            .find(|element| {
                matches!(
                    element.accessible_role(),
                    Some(
                        AccessibleRole::Button
                            | AccessibleRole::TextInput
                            | AccessibleRole::Switch
                            | AccessibleRole::Checkbox
                    )
                )
            })
            .unwrap_or_else(|| panic!("Missing control: {label}"));
        element.mock_single_click(PointerEventButton::Left);
    }

    #[test]
    fn first_click_activates_buttons_navigation_and_dialog_without_focus_interception() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1120., 780.));
        ui.show().unwrap();
        let calls = Rc::new(Cell::new(0));
        ui.on_add_proxy({
            let calls = calls.clone();
            let weak = ui.as_weak();
            move || {
                calls.set(calls.get() + 1);
                weak.unwrap().set_dialog(1);
            }
        });
        let saves = Rc::new(Cell::new(0));
        ui.on_save_proxy({
            let saves = saves.clone();
            move || saves.set(saves.get() + 1)
        });
        let toggles = Rc::new(Cell::new(0));
        ui.on_toggle({
            let toggles = toggles.clone();
            move || toggles.set(toggles.get() + 1)
        });
        ui.on_close_dialog({
            let weak = ui.as_weak();
            move || weak.unwrap().set_dialog(0)
        });

        click(&ui, "Прокси");
        click(&ui, "+ Добавить прокси");
        assert_eq!(calls.get(), 1, "the first click must open the editor");
        assert_eq!(ui.get_dialog(), 1);
        click(&ui, "+ Добавить прокси");
        assert_eq!(calls.get(), 1, "a modal must block controls behind it");
        click(&ui, "Название");
        ui.window()
            .dispatch_event(slint::platform::WindowEvent::KeyPressed { text: "X".into() });
        assert_eq!(
            ui.get_form_name(),
            "X",
            "a single click must focus the field"
        );
        click(&ui, "Сохранить");
        assert_eq!(
            saves.get(),
            1,
            "moving focus out of a field must not swallow a click"
        );
        ui.window()
            .dispatch_event(slint::platform::WindowEvent::KeyPressed {
                text: slint::platform::Key::Return.into(),
            });
        assert_eq!(saves.get(), 2, "keyboard activation must still work");
        click(&ui, "Отмена");
        assert_eq!(ui.get_dialog(), 0);
        click(&ui, "Правила");
        assert_eq!(ui.get_page(), 1);
        click(&ui, "Прокси");
        assert_eq!(ui.get_page(), 2);
        click(&ui, "Обзор");
        click(&ui, "Маршрутизация");
        assert_eq!(toggles.get(), 1);
        ui.set_busy(true);
        click(&ui, "Маршрутизация");
        assert_eq!(toggles.get(), 1, "busy controls must remain disabled");
    }

    #[test]
    fn rule_switch_disclosure_and_application_menu_activate_on_first_click() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1120., 780.));
        ui.set_rules(slint::ModelRc::new(slint::VecModel::from(vec![
            crate::RuleRow {
                id: "one".into(),
                name: "Game".into(),
                enabled: true,
                ..Default::default()
            },
        ])));
        ui.set_page(1);
        ui.show().unwrap();
        let toggles = Rc::new(Cell::new(0));
        let count = toggles.clone();
        ui.on_toggle_rule(move |id| {
            assert_eq!(id, "one");
            count.set(count.get() + 1);
        });
        click(&ui, "Правило Game");
        assert_eq!(toggles.get(), 1);
        ui.set_active(true);
        click(&ui, "Правило Game");
        assert_eq!(
            toggles.get(),
            2,
            "Running routes may be saved for an explicit restart"
        );
        ui.set_busy(true);
        click(&ui, "Правило Game");
        assert_eq!(
            toggles.get(),
            2,
            "Cannot mutate rules during a lifecycle transition"
        );
        ui.set_busy(false);
        ui.set_active(false);
        ui.set_dialog(2);
        click(&ui, "Дополнительные условия");
        assert!(ui.get_form_advanced());
        click(&ui, "Дополнительные условия");
        assert!(!ui.get_form_advanced());
        let choice = Rc::new(Cell::new(-1));
        let selected = choice.clone();
        ui.on_add_application(move |index| selected.set(index));
        for (index, label) in ["Вручную", "Из запущенных процессов", "Путь до EXE"]
            .into_iter()
            .enumerate()
        {
            click(&ui, "Добавить приложение");
            click(&ui, label);
            assert_eq!(choice.get(), index as i32);
        }
        ui.set_dialog(1);
        let calls = Rc::new(Cell::new(0));
        let count = calls.clone();
        ui.on_probe_proxy_form(move || count.set(count.get() + 1));
        click(&ui, "Проверить соединение");
        assert_eq!(calls.get(), 1);
        ui.set_probe_busy(true);
        click(&ui, "Проверяем…");
        assert_eq!(calls.get(), 1);
        ui.set_dialog(0);
        ui.set_page(4);
        let calls = Rc::new(Cell::new(0));
        let count = calls.clone();
        ui.on_set_autostart(move |_| count.set(count.get() + 1));
        click(&ui, "Запускать при входе в Windows");
        assert_eq!(calls.get(), 1);
        assert!(ui.get_autostart_enabled());
    }

    #[test]
    fn long_rule_form_scrolls_to_a_fully_visible_clickable_last_control() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.set_dialog(2);
        let rows = |values: &[&str]| {
            slint::ModelRc::new(slint::VecModel::from(
                values
                    .iter()
                    .map(|value| slint::SharedString::from(*value))
                    .collect::<Vec<_>>(),
            ))
        };
        ui.set_form_processes(rows(&["destiny2.exe", "destiny2launcher.exe", "steam.exe"]));
        ui.set_form_domains(rows(&[
            "*.steamserver.net",
            "*.deadorbit.net",
            "*.gravityshavings.net",
        ]));
        ui.set_form_show_paths(true);
        ui.set_form_paths(rows(&["C:\\Games\\Destiny 2\\destiny2.exe"]));
        ui.set_form_advanced(true);
        ui.set_form_networks(rows(&["192.0.2.0/24", "2001:db8::/32"]));
        ui.set_form_ports(rows(&["80", "443", "8000-9000"]));
        ui.show().unwrap();
        for (width, height) in [(960., 700.), (1120., 780.), (1280., 900.)] {
            ui.window().set_size(slint::LogicalSize::new(width, height));
            let scroll = ElementHandle::find_by_element_id(&ui, "MainWindow::rule-scroll")
                .next()
                .unwrap();
            scroll.scroll(0., -10000.);
            i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_secs(1));
            let field = ElementHandle::find_by_accessible_label(&ui, "443 или 8000-9000")
                .next()
                .unwrap();
            let bounds = (scroll.absolute_position(), scroll.size());
            let bottom = field.absolute_position().y + field.size().height;
            assert!(
                field.absolute_position().y >= bounds.0.y && bottom <= bounds.0.y + bounds.1.height,
                "Last control clipped at {width}x{height}: {bottom} outside {bounds:?}"
            );
            ui.set_form_new_port("".into());
            field.mock_single_click(PointerEventButton::Left);
            ui.window()
                .dispatch_event(slint::platform::WindowEvent::KeyPressed {
                    text: "12345".into(),
                });
            assert!(
                ui.get_form_new_port() == "12345",
                "Last field must focus on the first click"
            );
        }
    }

    #[test]
    fn update_banner_clicks_once_and_installation_requires_pause() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1120., 780.));
        ui.set_update_available(true);
        ui.set_update_version(true_proxy::updates::VERSION.into());
        ui.show().unwrap();
        let calls = Rc::new(Cell::new(0));
        let count = calls.clone();
        ui.on_update_now(move || count.set(count.get() + 1));
        click(&ui, "Обновить");
        assert_eq!(calls.get(), 1);
        ui.set_update_ready(true);
        ui.set_active(true);
        click(&ui, "Установить и перезапустить");
        assert_eq!(calls.get(), 1);
        ui.set_active(false);
        ui.set_busy(true);
        click(&ui, "Установить и перезапустить");
        assert_eq!(calls.get(), 1);
        ui.set_busy(false);
        click(&ui, "Установить и перезапустить");
        assert_eq!(calls.get(), 2);
    }
}
