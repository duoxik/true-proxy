use super::{Command, model, report};
use crate::{MainWindow, ProcessChoice};
use anyhow::{Result, ensure};
use slint::{ComponentHandle, Model, ModelRc, SharedString};
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
        if draft.trim().is_empty()
            || (kind == 2 && !ui.get_form_use_domains())
            || (kind >= 3 && !ui.get_form_advanced())
        {
            continue;
        }
        let mut rows = values(get(ui, kind));
        editor::append(&mut rows, editor::entries(kind, &draft)?);
        changes.push((kind, rows));
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
                    if kind == 2 {
                        ui.set_form_use_domains(true);
                    }
                    if kind >= 3 {
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
            let mut rows = values(get(&ui, kind));
            if index >= 0 && (index as usize) < rows.len() {
                rows.remove(index as usize);
                put(&ui, kind, rows);
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
