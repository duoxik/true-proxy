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
                    "Could not install the update: {error:#}"
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
    use slint::{ComponentHandle, Model, platform::PointerEventButton};
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
    fn desktop_navigation_fits_supported_sizes_in_one_window() {
        i_slint_backend_testing::init_no_event_loop();
        for (width, height) in [(960., 640.), (1240., 780.)] {
            let ui = MainWindow::new().unwrap();
            ui.window().set_size(slint::LogicalSize::new(width, height));
            let hides = Rc::new(Cell::new(0));
            let calls = hides.clone();
            ui.window().on_close_requested(move || {
                calls.set(calls.get() + 1);
                slint::CloseRequestResponse::HideWindow
            });
            ui.show().unwrap();
            for (label, page) in [
                ("Dashboard", 0),
                ("Rules", 1),
                ("Proxies", 2),
                ("Connections", 3),
                ("Logs", 5),
                ("Settings", 4),
            ] {
                let button = ElementHandle::find_by_accessible_label(&ui, label)
                    .find(|element| element.accessible_role() == Some(AccessibleRole::Button))
                    .unwrap();
                let position = button.absolute_position();
                let size = button.size();
                assert!(position.x >= 0. && position.y >= 0.);
                assert!(position.x + size.width <= width + 0.1);
                assert!(position.y + size.height <= height + 0.1);
                button.mock_single_click(PointerEventButton::Left);
                assert_eq!(ui.get_page(), page);
            }
            click(&ui, "Logs");
            let logs = ui.global::<TechnicalLogs>();
            assert!(!logs.get_follow());
            click(&ui, "Follow: Off");
            assert!(logs.get_follow());
            click(&ui, "Follow: On");
            assert!(!logs.get_follow());
            assert!(ui.window().size().width <= width as u32);
            assert!(ui.window().size().height <= height as u32);
            ui.window()
                .dispatch_event(slint::platform::WindowEvent::CloseRequested);
            assert_eq!(hides.get(), 1);
            assert!(!ui.window().is_visible());
        }
    }

    #[test]
    fn installed_xray_sections_open_from_the_sidebar_on_first_click() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1240., 780.));
        ui.show().unwrap();
        let xray = ui.global::<XrayModule>();
        let sections = [
            "Xray Dashboard",
            "Xray Profiles",
            "Xray General",
            "Xray DNS",
            "Xray Fallbacks",
            "Xray Connections",
            "Xray Logs",
        ];
        for label in sections {
            assert!(
                ElementHandle::find_by_accessible_label(&ui, label)
                    .next()
                    .is_none()
            );
        }

        xray.set_installed(true);
        for (heading, link) in [
            ("PROXY", "Dashboard"),
            ("NETWORK", "Connections"),
            ("SYSTEM", "Settings"),
            ("X-RAY", "Xray Dashboard"),
        ] {
            let group = ElementHandle::find_by_accessible_label(&ui, heading)
                .find(|element| element.accessible_role() == Some(AccessibleRole::Button))
                .unwrap();
            assert_eq!(group.accessible_expanded(), Some(true));
            group.mock_single_click(PointerEventButton::Left);
            assert_eq!(group.accessible_expanded(), Some(false));
            assert!(
                ElementHandle::find_by_accessible_label(&ui, link)
                    .find(|element| element.accessible_role() == Some(AccessibleRole::Button))
                    .is_none()
            );
            assert_eq!(ui.get_page(), 0);
            group.mock_single_click(PointerEventButton::Left);
            assert_eq!(group.accessible_expanded(), Some(true));
        }

        let settings = ElementHandle::find_by_accessible_label(&ui, "Settings")
            .find(|element| element.accessible_role() == Some(AccessibleRole::Button))
            .unwrap();
        let sidebar_x = settings.absolute_position().x;
        for (section, label) in sections.into_iter().enumerate() {
            let button = ElementHandle::find_by_accessible_label(&ui, label)
                .find(|element| element.accessible_role() == Some(AccessibleRole::Button))
                .unwrap();
            assert!((button.absolute_position().x - sidebar_x).abs() < 24.);
            assert_eq!(button.size().height, settings.size().height);
            button.mock_single_click(PointerEventButton::Left);
            assert_eq!(ui.get_page(), 6);
            assert_eq!(xray.get_section(), section as i32);
        }
        ui.window().set_size(slint::LogicalSize::new(960., 640.));
        ui.set_page(0);
        ui.window()
            .dispatch_event(slint::platform::WindowEvent::PointerScrolled {
                position: slint::LogicalPosition::new(90., 455.),
                delta_x: 0.,
                delta_y: -1000.,
            });
        click(&ui, "Xray Logs");
        assert_eq!(ui.get_page(), 6);
        assert_eq!(xray.get_section(), 6);
    }

    #[test]
    fn xray_profiles_refresh_only_the_clicked_subscription() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1240., 780.));
        let xray = ui.global::<XrayModule>();
        xray.set_installed(true);
        let profile = |id: &str, name: &str| XrayProfileRow {
            id: id.into(),
            name: name.into(),
            ..Default::default()
        };
        xray.set_profiles(slint::ModelRc::new(slint::VecModel::from(vec![profile(
            "manual-id",
            "Manual node",
        )])));
        xray.set_subscriptions(slint::ModelRc::new(slint::VecModel::from(vec![
            XraySubscriptionGroup {
                id: "source-a".into(),
                name: "Subscription 1".into(),
                profiles: slint::ModelRc::new(slint::VecModel::from(vec![
                    profile("profile-a1", "Node A1"),
                    profile("profile-a2", "Node A2"),
                ])),
            },
            XraySubscriptionGroup {
                id: "source-b".into(),
                name: "Subscription 2".into(),
                profiles: slint::ModelRc::new(slint::VecModel::from(vec![profile(
                    "profile-b1",
                    "Node B1",
                )])),
            },
        ])));
        let refreshed = Rc::new(Cell::new(slint::SharedString::default()));
        xray.on_refresh_subscription({
            let refreshed = refreshed.clone();
            move |id| refreshed.set(id)
        });
        ui.show().unwrap();
        click(&ui, "Xray Profiles");

        for name in ["Manual node", "Node A1", "Node A2", "Node B1"] {
            assert!(
                ElementHandle::find_by_accessible_label(&ui, &format!("Activate {name}"))
                    .next()
                    .is_some()
            );
            assert!(
                ElementHandle::find_by_accessible_label(
                    &ui,
                    &format!("Refresh subscription for {name}"),
                )
                .next()
                .is_none()
            );
        }
        for (label, id) in [
            ("Refresh Subscription 1", "source-a"),
            ("Refresh Subscription 2", "source-b"),
        ] {
            assert_eq!(
                ElementHandle::find_by_accessible_label(&ui, label).count(),
                1
            );
            click(&ui, label);
            assert_eq!(refreshed.take().as_str(), id);
        }
    }

    #[test]
    fn first_click_activates_buttons_navigation_and_dialog_without_focus_interception() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1240., 780.));
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

        for label in ["Rule Local", "Rule Fallback"] {
            let switch = ElementHandle::find_by_accessible_label(&ui, label)
                .find(|element| element.accessible_role() == Some(AccessibleRole::Switch))
                .unwrap();
            assert_eq!(switch.accessible_checked(), Some(true));
            assert_eq!(switch.accessible_enabled(), Some(false));
        }
        click(&ui, "View Rules");
        assert_eq!(ui.get_page(), 1);
        assert_eq!(ui.get_dialog(), 0);
        click(&ui, "Dashboard");
        click(&ui, "View Proxies");
        assert_eq!(ui.get_page(), 2);
        assert_eq!(ui.get_dialog(), 0);
        click(&ui, "Add Proxy");
        assert_eq!(calls.get(), 1, "the first click must open the editor");
        assert_eq!(ui.get_dialog(), 1);
        click(&ui, "Add Proxy");
        assert_eq!(calls.get(), 1, "a modal must block controls behind it");
        click(&ui, "Proxy Name");
        ui.window()
            .dispatch_event(slint::platform::WindowEvent::KeyPressed { text: "X".into() });
        assert_eq!(
            ui.get_form_name(),
            "X",
            "a single click must focus the field"
        );
        click(&ui, "Save");
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
        click(&ui, "Cancel");
        assert_eq!(ui.get_dialog(), 0);
        click(&ui, "Rules");
        assert_eq!(ui.get_page(), 1);
        click(&ui, "Proxies");
        assert_eq!(ui.get_page(), 2);
        click(&ui, "Dashboard");
        click(&ui, "Routing");
        assert_eq!(toggles.get(), 1);
        ui.set_busy(true);
        click(&ui, "Routing");
        assert_eq!(toggles.get(), 1, "busy controls must remain disabled");
    }

    #[test]
    fn local_network_card_is_always_first_and_can_only_edit_cidrs() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1240., 780.));
        ui.set_page(1);
        ui.show().unwrap();
        let card = ElementHandle::find_by_element_id(&ui, "MainWindow::local-network-card")
            .next()
            .expect("The fixed local route must exist even with an empty profile");
        let labels = card.query_descendants().find_all();
        assert!(
            labels
                .iter()
                .any(|element| element.accessible_label().as_deref() == Some("1. Local"))
        );
        assert!(
            labels
                .iter()
                .any(|element| element.accessible_label().as_deref() == Some("Direct"))
        );
        assert_eq!(
            labels
                .iter()
                .filter(|element| element.accessible_enabled() != Some(false))
                .filter_map(|element| {
                    match element.accessible_role() {
                        Some(
                            AccessibleRole::Button
                            | AccessibleRole::Switch
                            | AccessibleRole::Checkbox
                            | AccessibleRole::TextInput,
                        ) => element.accessible_label(),
                        _ => None,
                    }
                })
                .collect::<Vec<_>>(),
            ["Edit local network"],
            "The local route must only expose CIDR editing"
        );
        for label in ["Rule Local", "Delete local rule"] {
            let control = labels
                .iter()
                .find(|element| element.accessible_label().as_deref() == Some(label))
                .unwrap();
            assert_eq!(control.accessible_enabled(), Some(false));
        }
        assert!(!labels.iter().any(|element| {
            element
                .accessible_label()
                .is_some_and(|label| label.starts_with("Move local rule"))
        }));

        ui.set_rules(slint::ModelRc::new(slint::VecModel::from(vec![
            crate::RuleRow {
                id: "game".into(),
                name: "Game".into(),
                route: "Direct".into(),
                enabled: true,
                priority: 2,
            },
        ])));
        let game = ElementHandle::find_by_accessible_label(&ui, "2. Game")
            .next()
            .unwrap();
        let fallback = ElementHandle::find_by_element_id(&ui, "MainWindow::fallback-card")
            .next()
            .unwrap();
        assert!(card.absolute_position().y + card.size().height <= game.absolute_position().y);
        assert!(game.absolute_position().y < fallback.absolute_position().y);
        let first_up = ElementHandle::find_by_accessible_label(&ui, "Move rule up")
            .next()
            .unwrap();
        assert_eq!(
            first_up.accessible_enabled(),
            Some(false),
            "An ordinary rule cannot move above the fixed route"
        );
        ui.set_busy(true);
        assert!(
            ElementHandle::find_by_element_id(&ui, "MainWindow::local-network-card")
                .next()
                .is_some()
        );
        assert_eq!(ui.get_dialog(), 0);
    }

    #[test]
    fn rule_switch_disclosure_and_application_menu_activate_on_first_click() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1240., 780.));
        ui.set_rules(slint::ModelRc::new(slint::VecModel::from(vec![
            crate::RuleRow {
                id: "one".into(),
                name: "Game".into(),
                route: "Direct".into(),
                enabled: true,
                priority: 2,
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
        click(&ui, "Rule Game");
        assert_eq!(toggles.get(), 1);
        ui.set_active(true);
        click(&ui, "Rule Game");
        assert_eq!(
            toggles.get(),
            2,
            "Running routes may be saved for an explicit restart"
        );
        ui.set_busy(true);
        click(&ui, "Rule Game");
        assert_eq!(
            toggles.get(),
            2,
            "Cannot mutate rules during a lifecycle transition"
        );
        ui.set_busy(false);
        ui.set_active(false);
        click(&ui, "Dashboard");
        click(&ui, "Rule Game");
        assert_eq!(toggles.get(), 3, "The Dashboard switch edits the same rule");
        click(&ui, "Rules");
        ui.set_dialog(2);
        let protocol = ElementHandle::find_by_element_id(&ui, "ThemedComboBox::control")
            .find(|control| control.accessible_value().as_deref() == Some("TCP + UDP"))
            .expect("Protocol selector");
        protocol.mock_single_click(PointerEventButton::Left);
        assert_eq!(protocol.accessible_expanded(), Some(true));
        for key in [
            slint::platform::Key::DownArrow,
            slint::platform::Key::Return,
        ] {
            ui.window()
                .dispatch_event(slint::platform::WindowEvent::KeyPressed { text: key.into() });
        }
        assert_eq!(ui.get_form_protocol(), 1);
        click(&ui, "Additional conditions");
        assert!(ui.get_form_advanced());
        click(&ui, "Additional conditions");
        assert!(!ui.get_form_advanced());
        let choice = Rc::new(Cell::new(-1));
        let selected = choice.clone();
        ui.on_add_application(move |index| selected.set(index));
        for (index, label) in ["Manual entry", "Running processes", "Executable path"]
            .into_iter()
            .enumerate()
        {
            click(&ui, "Add application");
            click(&ui, label);
            assert_eq!(choice.get(), index as i32);
        }
        ui.set_dialog(1);
        let calls = Rc::new(Cell::new(0));
        let count = calls.clone();
        ui.on_probe_proxy_form(move || count.set(count.get() + 1));
        click(&ui, "Check");
        assert_eq!(calls.get(), 1);
        ui.set_probe_busy(true);
        click(&ui, "Checking…");
        assert_eq!(calls.get(), 1);
        ui.set_dialog(0);
        ui.set_page(4);
        let calls = Rc::new(Cell::new(0));
        let count = calls.clone();
        ui.on_set_autostart(move |_| count.set(count.get() + 1));
        let settings = ElementHandle::find_by_element_id(&ui, "MainWindow::settings-scroll")
            .next()
            .unwrap();
        let startup =
            ElementHandle::find_by_accessible_label(&ui, "Start when I sign in to Windows")
                .find(|element| element.accessible_role() == Some(AccessibleRole::Checkbox))
                .unwrap();
        let bottom = startup.absolute_position().y + startup.size().height;
        let viewport_bottom = settings.absolute_position().y + settings.size().height;
        if bottom > viewport_bottom {
            settings.scroll(0., viewport_bottom - bottom - 8.);
        }
        click(&ui, "Start when I sign in to Windows");
        assert_eq!(calls.get(), 1);
        assert!(ui.get_autostart_enabled());
    }

    #[test]
    fn every_condition_list_has_a_separate_remove_button_with_an_eight_pixel_gap() {
        i_slint_backend_testing::init_no_event_loop();
        for (kind, value) in [
            (0, "DeleteMe.exe"),
            (1, "C:\\Games\\DeleteMe.exe"),
            (2, "*.delete.test"),
            (3, "192.0.2.0/24"),
            (4, "4242"),
        ] {
            let ui = MainWindow::new().unwrap();
            ui.window().set_size(slint::LogicalSize::new(1240., 780.));
            ui.set_dialog(2);
            ui.set_form_show_paths(kind == 1);
            ui.set_form_advanced(kind >= 2);
            let rows = slint::ModelRc::new(slint::VecModel::from(vec![slint::SharedString::from(
                value,
            )]));
            match kind {
                0 => ui.set_form_processes(rows),
                1 => ui.set_form_paths(rows),
                2 => ui.set_form_domains(rows),
                3 => ui.set_form_networks(rows),
                _ => ui.set_form_ports(rows),
            }
            let calls = Rc::new(Cell::new(0));
            let count = calls.clone();
            let weak = ui.as_weak();
            ui.on_remove_condition(move |actual, index| {
                assert_eq!((actual, index), (kind, 0));
                count.set(count.get() + 1);
                let ui = weak.unwrap();
                let empty = slint::ModelRc::new(slint::VecModel::<slint::SharedString>::default());
                match actual {
                    0 => ui.set_form_processes(empty),
                    1 => ui.set_form_paths(empty),
                    2 => ui.set_form_domains(empty),
                    3 => ui.set_form_networks(empty),
                    _ => ui.set_form_ports(empty),
                }
            });
            ui.show().unwrap();
            let scroll = ElementHandle::find_by_element_id(&ui, "MainWindow::rule-scroll")
                .next()
                .unwrap();
            let remove_label = format!("Remove {value}");
            let find_remove = || ElementHandle::find_by_accessible_label(&ui, &remove_label).next();
            let remove = find_remove()
                .or_else(|| {
                    scroll.scroll(0., -500.);
                    find_remove()
                })
                .unwrap_or_else(|| panic!("Missing removal control for kind {kind}: {value}"));
            let scroll_bottom = scroll.absolute_position().y + scroll.size().height;
            let button_bottom = remove.absolute_position().y + remove.size().height;
            if button_bottom > scroll_bottom {
                scroll.scroll(0., scroll_bottom - button_bottom - 8.);
            }
            let field = ElementHandle::find_by_element_id(&ui, "ListEditor::value-field")
                .find(|field| {
                    field
                        .query_descendants()
                        .find_all()
                        .iter()
                        .any(|text| text.accessible_value().as_deref() == Some(value))
                })
                .expect("Missing condition value field");
            let field_right = field.absolute_position().x + field.size().width;
            assert!(
                remove.absolute_position().x - field_right >= 7.9,
                "Delete button overlaps field for kind {kind}"
            );
            remove.mock_single_click(PointerEventButton::Left);
            assert_eq!(
                calls.get(),
                1,
                "Delete must work on the first click for kind {kind}"
            );
            assert_eq!(
                ElementHandle::find_by_accessible_label(&ui, &remove_label).count(),
                0
            );
            ui.hide().unwrap();
        }
    }

    #[test]
    fn long_rule_form_scrolls_to_a_fully_visible_clickable_last_control() {
        i_slint_backend_testing::init_no_event_loop();
        for (width, height) in [(960., 640.), (1120., 700.), (1240., 780.)] {
            let ui = MainWindow::new().unwrap();
            ui.window().set_size(slint::LogicalSize::new(width, height));
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
            ui.set_form_ports(rows(&["80", "443", ""]));
            let weak = ui.as_weak();
            ui.on_edit_condition(move |kind, index, text| {
                assert_eq!(kind, 4);
                let ports = weak.unwrap().get_form_ports();
                ports
                    .as_any()
                    .downcast_ref::<slint::VecModel<slint::SharedString>>()
                    .unwrap()
                    .set_row_data(index as usize, text);
            });
            ui.show().unwrap();
            let scroll = ElementHandle::find_by_element_id(&ui, "MainWindow::rule-scroll")
                .next()
                .unwrap();
            scroll.scroll(0., -10000.);
            i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_secs(1));
            let field = ElementHandle::find_by_accessible_label(&ui, "Ports · row 3")
                .next()
                .unwrap();
            let bounds = (scroll.absolute_position(), scroll.size());
            let bottom = field.absolute_position().y + field.size().height;
            assert!(
                field.absolute_position().y >= bounds.0.y && bottom <= bounds.0.y + bounds.1.height,
                "Last control clipped at {width}x{height}: {bottom} outside {bounds:?}"
            );
            field.mock_single_click(PointerEventButton::Left);
            ui.window()
                .dispatch_event(slint::platform::WindowEvent::KeyPressed {
                    text: "12345".into(),
                });
            assert!(
                ui.get_form_ports().row_data(2).as_deref() == Some("12345"),
                "Last field must focus on the first click"
            );
            ui.hide().unwrap();
        }
    }

    #[test]
    fn update_banner_clicks_once_and_installation_requires_pause() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1240., 780.));
        ui.set_update_available(true);
        ui.set_update_version(true_proxy::updates::VERSION.into());
        ui.show().unwrap();
        let calls = Rc::new(Cell::new(0));
        let count = calls.clone();
        ui.on_update_now(move || count.set(count.get() + 1));
        click(&ui, "Update");
        assert_eq!(calls.get(), 1);
        ui.set_update_ready(true);
        ui.set_active(true);
        click(&ui, "Install and Restart");
        assert_eq!(calls.get(), 1);
        ui.set_active(false);
        ui.set_busy(true);
        click(&ui, "Install and Restart");
        assert_eq!(calls.get(), 1);
        ui.set_busy(false);
        click(&ui, "Install and Restart");
        assert_eq!(calls.get(), 2);
    }
}
