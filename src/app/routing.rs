use super::{Command, model, report};
use crate::{MainWindow, ProcessChoice};
use anyhow::{Result, ensure};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
use std::sync::mpsc::SyncSender;
use true_proxy::{editor, platform::RunningProcess};

pub fn strings(values: Vec<String>) -> ModelRc<SharedString> {
    model(values.into_iter().map(Into::into).collect())
}
pub fn values(rows: ModelRc<SharedString>) -> Vec<String> {
    rows.iter().map(|row| row.to_string()).collect()
}
pub fn flush_drafts(ui: &MainWindow) -> Result<()> {
    let drafts = [
        (0, ui.get_form_new_process()),
        (1, ui.get_form_new_path()),
        (2, ui.get_form_new_domain()),
        (3, ui.get_form_new_network()),
        (4, ui.get_form_new_port()),
    ];
    let mut changes = Vec::new();
    for (kind, draft) in drafts {
        let mut normalized = Vec::new();
        for row in values(get(ui, kind)).into_iter().chain([draft.to_string()]) {
            editor::append(&mut normalized, editor::entries(kind, &row)?);
        }
        changes.push((kind, normalized));
    }
    for (kind, rows) in changes {
        put(ui, kind, rows);
    }
    ui.set_form_new_process("".into());
    ui.set_form_new_path("".into());
    ui.set_form_new_domain("".into());
    ui.set_form_new_network("".into());
    ui.set_form_new_port("".into());
    Ok(())
}
fn get(ui: &MainWindow, kind: i32) -> ModelRc<SharedString> {
    match kind {
        0 => ui.get_form_processes(),
        1 => ui.get_form_paths(),
        2 => ui.get_form_domains(),
        3 => ui.get_form_networks(),
        _ => ui.get_form_ports(),
    }
}
fn put(ui: &MainWindow, kind: i32, values: Vec<String>) {
    let rows = strings(values);
    match kind {
        0 => ui.set_form_processes(rows),
        1 => ui.set_form_paths(rows),
        2 => ui.set_form_domains(rows),
        3 => ui.set_form_networks(rows),
        _ => ui.set_form_ports(rows),
    }
}

fn new_row(ui: &MainWindow, kind: i32) {
    let rows = get(ui, kind);
    if let Some(model) = rows.as_any().downcast_ref::<VecModel<SharedString>>() {
        model.push(SharedString::default());
    } else {
        let mut values = values(rows);
        values.push(String::new());
        put(ui, kind, values);
    }
    if kind == 1 {
        ui.set_form_show_paths(true);
    }
    if kind >= 2 {
        ui.set_form_advanced(true);
    }
    ui.set_notice("".into());
}

fn edit_row(ui: &MainWindow, kind: i32, index: i32, value: SharedString) {
    let rows = get(ui, kind);
    if index < 0 || index as usize >= rows.row_count() {
        return;
    }
    if let Some(model) = rows.as_any().downcast_ref::<VecModel<SharedString>>() {
        // Keep this model and the row item alive while typing, including caret.
        model.set_row_data(index as usize, value);
    } else {
        let mut values = values(rows);
        values[index as usize] = value.to_string();
        put(ui, kind, values);
    }
}
pub fn filter_processes(ui: &MainWindow) {
    let query = ui.get_process_query().to_lowercase();
    let rows = ui.get_all_processes().iter().collect::<Vec<_>>();
    ui.set_process_selected_count(rows.iter().filter(|row| row.selected).count() as i32);
    ui.set_process_choices(model(
        rows.into_iter()
            .filter(|row| {
                query.is_empty()
                    || row.name.to_lowercase().contains(&query)
                    || row.path.to_lowercase().contains(&query)
                    || row.pids.contains(&query)
            })
            .collect(),
    ));
}
pub fn set_processes(ui: &MainWindow, processes: Vec<RunningProcess>) {
    let selected = ui
        .get_all_processes()
        .iter()
        .filter(|row| row.selected)
        .map(|row| row.key)
        .collect::<std::collections::HashSet<_>>();
    ui.set_all_processes(model(
        processes
            .into_iter()
            .map(|process| {
                let key: SharedString = format!(
                    "{}|{}",
                    process.name.to_lowercase(),
                    process.path.to_lowercase()
                )
                .into();
                ProcessChoice {
                    selected: selected.contains(&key),
                    key,
                    name: process.name.into(),
                    path: process.path.into(),
                    instances: process.pids.len() as i32,
                    pids: process
                        .pids
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                        .into(),
                }
            })
            .collect(),
    ));
    filter_processes(ui);
}
pub fn wire(ui: &MainWindow, sender: SyncSender<Command>) {
    let weak = ui.as_weak();
    ui.on_add_application(move |kind| {
        if let Some(ui) = weak.upgrade() {
            match kind {
                0 => ui.invoke_new_condition(0),
                1 => ui.invoke_open_processes(),
                2 => match true_proxy::platform::choose_executable() {
                    Ok(Some(path)) => ui.invoke_add_condition(1, path.into()),
                    Ok(None) => {}
                    Err(error) => report(&ui, Err(error)),
                },
                _ => {}
            }
        }
    });
    let weak = ui.as_weak();
    ui.on_new_condition(move |kind| {
        if let Some(ui) = weak.upgrade()
            && (0..=4).contains(&kind)
        {
            new_row(&ui, kind);
        }
    });
    let weak = ui.as_weak();
    ui.on_edit_condition(move |kind, index, value| {
        if let Some(ui) = weak.upgrade()
            && (0..=4).contains(&kind)
        {
            edit_row(&ui, kind, index, value);
        }
    });
    let weak = ui.as_weak();
    ui.on_add_condition(move |kind, input| {
        if let Some(ui) = weak.upgrade() {
            report(
                &ui,
                (|| -> Result<()> {
                    let additions = editor::entries(kind, &input)?;
                    let mut rows = values(get(&ui, kind));
                    editor::append(&mut rows, additions);
                    put(&ui, kind, rows);
                    if kind == 1 {
                        ui.set_form_show_paths(true);
                    }
                    if kind >= 2 {
                        ui.set_form_advanced(true);
                    }
                    ui.set_notice("".into());
                    Ok(())
                })(),
            );
        }
    });
    let weak = ui.as_weak();
    ui.on_remove_condition(move |kind, index| {
        if let Some(ui) = weak.upgrade() {
            let rows = get(&ui, kind);
            if index >= 0 && (index as usize) < rows.row_count() {
                if let Some(model) = rows.as_any().downcast_ref::<VecModel<SharedString>>() {
                    model.remove(index as usize);
                } else {
                    let mut values = values(rows);
                    values.remove(index as usize);
                    put(&ui, kind, values);
                }
            }
        }
    });
    let weak = ui.as_weak();
    ui.on_filter_processes(move || {
        if let Some(ui) = weak.upgrade() {
            filter_processes(&ui);
        }
    });
    let weak = ui.as_weak();
    ui.on_toggle_process(move |key| {
        if let Some(ui) = weak.upgrade() {
            let mut rows = ui.get_all_processes().iter().collect::<Vec<_>>();
            if let Some(row) = rows.iter_mut().find(|row| row.key == key) {
                row.selected = !row.selected;
            }
            ui.set_all_processes(model(rows));
            filter_processes(&ui);
        }
    });
    let weak = ui.as_weak();
    ui.on_refresh_processes(move || {
        if let Some(ui) = weak.upgrade()
            && !ui.get_processes_busy()
        {
            match sender.try_send(Command::Processes) {
                Ok(()) => ui.set_processes_busy(true),
                Err(_) => ui.set_notice("Сетевой слой занят. Повторите обновление списка.".into()),
            }
        }
    });
    let weak = ui.as_weak();
    ui.on_open_processes(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_notice("".into());
            ui.set_process_query("".into());
            ui.set_process_picker(true);
            filter_processes(&ui);
            ui.invoke_refresh_processes();
        }
    });
    let weak = ui.as_weak();
    ui.on_add_selected_processes(move || {
        if let Some(ui) = weak.upgrade() {
            report(
                &ui,
                (|| -> Result<()> {
                    let selected = ui
                        .get_all_processes()
                        .iter()
                        .filter(|row| row.selected)
                        .collect::<Vec<_>>();
                    ensure!(!selected.is_empty(), "Выберите хотя бы один процесс");
                    let kind = i32::from(ui.get_process_by_path());
                    let mut rows = values(get(&ui, kind));
                    for row in selected {
                        ensure!(
                            kind == 0 || !row.path.is_empty(),
                            "Для {} путь недоступен. Добавьте процесс по имени EXE.",
                            row.name
                        );
                        editor::append(
                            &mut rows,
                            vec![if kind == 0 {
                                row.name.to_string()
                            } else {
                                row.path.to_string()
                            }],
                        );
                    }
                    put(&ui, kind, rows);
                    if kind == 1 {
                        ui.set_form_show_paths(true);
                    }
                    ui.set_process_picker(false);
                    ui.set_notice("".into());
                    Ok(())
                })(),
            );
        }
    });
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};

    fn click(ui: &MainWindow, label: &str) {
        ElementHandle::find_by_accessible_label(ui, label)
            .find(|element| {
                matches!(
                    element.accessible_role(),
                    Some(AccessibleRole::Button | AccessibleRole::TextInput)
                )
            })
            .unwrap_or_else(|| panic!("Missing control {label}"))
            .mock_single_click(slint::platform::PointerEventButton::Left);
    }

    #[test]
    fn add_blank_edit_in_place_and_manual_process_choice_keep_model_and_caret() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1120., 900.));
        ui.set_dialog(2);
        ui.set_form_advanced(true);
        let (sender, _receiver) = std::sync::mpsc::sync_channel(2);
        wire(&ui, sender);
        ui.show().unwrap();
        click(&ui, "Добавить Домены");
        assert_eq!(values(ui.get_form_domains()), [""]);
        let before = ui.get_form_domains();
        click(&ui, "Домены · строка 1");
        for text in [
            "a".into(),
            "b".into(),
            slint::platform::Key::LeftArrow.into(),
            "x".into(),
        ] {
            ui.window()
                .dispatch_event(slint::platform::WindowEvent::KeyPressed { text });
        }
        assert_eq!(
            values(ui.get_form_domains()),
            ["axb"],
            "Typing and moving the caret must preserve focus"
        );
        let after = ui.get_form_domains();
        assert!(std::ptr::eq(
            before
                .as_any()
                .downcast_ref::<VecModel<SharedString>>()
                .unwrap(),
            after
                .as_any()
                .downcast_ref::<VecModel<SharedString>>()
                .unwrap()
        ));
        click(&ui, "Удалить axb");
        assert_eq!(ui.get_form_domains().row_count(), 0);
        click(&ui, "Добавить приложение");
        click(&ui, "Вручную");
        assert_eq!(values(ui.get_form_processes()), [""]);
        click(&ui, "Приложения по имени EXE · строка 1");
        for text in ["g", "a"] {
            ui.window()
                .dispatch_event(slint::platform::WindowEvent::KeyPressed { text: text.into() });
        }
        assert_eq!(values(ui.get_form_processes()), ["ga"]);
        click(&ui, "Добавить приложение");
        click(&ui, "Из запущенных процессов");
        assert!(ui.get_process_picker());
        // File selection remains the third menu entry; other UI tests replace
        // its callback so checking it never opens a real native file dialog.
    }

    #[test]
    fn save_validation_normalizes_all_lists_atomically_and_ignores_blank_rows() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.set_form_processes(strings(vec![
            " Game.exe ".into(),
            "game.exe".into(),
            "".into(),
        ]));
        ui.set_form_domains(strings(vec!["*.EXAMPLE.com.".into()]));
        ui.set_form_networks(strings(vec!["bad cidr".into()]));
        ui.set_form_new_port("443".into());
        assert!(flush_drafts(&ui).is_err());
        assert_eq!(
            values(ui.get_form_processes()),
            [" Game.exe ", "game.exe", ""]
        );
        assert_eq!(values(ui.get_form_domains()), ["*.EXAMPLE.com."]);
        assert_eq!(ui.get_form_new_port(), "443");
        ui.set_form_networks(strings(vec!["192.0.2.1".into(), "".into()]));
        flush_drafts(&ui).unwrap();
        assert_eq!(values(ui.get_form_processes()), ["Game.exe"]);
        assert_eq!(values(ui.get_form_domains()), ["*.example.com"]);
        assert_eq!(values(ui.get_form_networks()), ["192.0.2.1/32"]);
        assert_eq!(values(ui.get_form_ports()), ["443"]);
        assert!(ui.get_form_new_port().is_empty());
        for (kind, invalid) in [
            (0, "*.exe"),
            (1, "relative.exe"),
            (2, "https://bad.example"),
            (3, "300.0.0.1"),
            (4, "70000"),
        ] {
            put(&ui, kind, vec![invalid.into()]);
            assert!(flush_drafts(&ui).is_err());
            assert_eq!(values(get(&ui, kind)), [invalid]);
            put(&ui, kind, vec![]);
        }
    }

    #[test]
    fn collapsed_conditions_keep_values_and_flush_uncommitted_drafts() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.set_form_advanced(false);
        ui.set_form_domains(strings(vec!["*.example.com".into()]));
        ui.set_form_new_domain("other.example".into());
        ui.set_form_new_network("192.0.2.0/24".into());
        ui.set_form_new_port("8000-9000".into());
        flush_drafts(&ui).unwrap();
        assert_eq!(
            values(ui.get_form_domains()),
            ["*.example.com", "other.example"]
        );
        assert_eq!(values(ui.get_form_networks()), ["192.0.2.0/24"]);
        assert_eq!(values(ui.get_form_ports()), ["8000-9000"]);
    }
    #[test]
    fn process_selection_survives_filtering_and_adds_persistent_names() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        let (sender, _receiver) = std::sync::mpsc::sync_channel(2);
        wire(&ui, sender);
        set_processes(
            &ui,
            vec![
                RunningProcess {
                    name: "game.exe".into(),
                    path: "C:\\Games\\game.exe".into(),
                    pids: vec![10, 11],
                },
                RunningProcess {
                    name: "chat.exe".into(),
                    path: "".into(),
                    pids: vec![12],
                },
            ],
        );
        let key = ui.get_all_processes().row_data(0).unwrap().key;
        ui.invoke_toggle_process(key);
        ui.set_process_query("chat".into());
        ui.invoke_filter_processes();
        assert_eq!(ui.get_process_choices().row_count(), 1);
        assert_eq!(ui.get_process_selected_count(), 1);
        ui.invoke_add_selected_processes();
        assert_eq!(values(ui.get_form_processes()), ["game.exe"]);
        assert!(!ui.get_process_picker());
    }
}
