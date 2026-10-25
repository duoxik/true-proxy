use super::{State, json_highlight, model, pending, proxies, report};
use crate::{JsonLine, MainWindow};
use anyhow::Result;
use slint::{ComponentHandle, SharedString};
use std::{
    cell::RefCell,
    path::PathBuf,
    rc::Rc,
    sync::{Arc, Mutex},
    time::Duration,
};
use true_proxy::profile::{MAX_BYTES, Profile};

#[derive(Default)]
struct Document {
    text: SharedString,
    starts: Vec<usize>,
    highlightable: bool,
}
fn paint(ui: &MainWindow, document: &Document) {
    if ui.get_dialog() != 3 {
        return;
    }
    if document.text != ui.get_import_json() || !document.highlightable {
        ui.set_import_lines(model(vec![]));
        return;
    }
    let first = ui.get_import_first_line().max(0) as usize;
    let count = ui.get_import_visible_lines().clamp(1, 200) as usize;
    ui.set_import_lines(model(
        document
            .starts
            .iter()
            .enumerate()
            .skip(first)
            .take(count)
            .map(|(number, &start)| {
                let end = document
                    .starts
                    .get(number + 1)
                    .copied()
                    .unwrap_or(document.text.len());
                let line = document.text[start..end].trim_end_matches(['\r', '\n']);
                JsonLine {
                    number: number as i32,
                    text: json_highlight::line(line),
                }
            })
            .collect(),
    ));
}
fn validate(ui: &MainWindow, document: &RefCell<Document>) {
    let text = ui.get_import_json();
    ui.set_import_error("".into());
    ui.set_import_valid(false);
    if text.is_empty() {
        ui.set_import_summary("Вставьте JSON конфигурации для проверки.".into());
        *document.borrow_mut() = Document::default();
        ui.set_import_lines(model(vec![]));
        return;
    }
    if text.len() <= MAX_BYTES {
        let starts = std::iter::once(0)
            .chain(text.match_indices('\n').map(|(at, _)| at + 1))
            .collect();
        *document.borrow_mut() = Document {
            text: text.clone(),
            starts,
            highlightable: text.lines().all(|line| line.len() <= 8192),
        };
        paint(ui, &document.borrow());
    } else {
        *document.borrow_mut() = Document::default();
        ui.set_import_lines(model(vec![]));
    }
    match Profile::parse(&text) {
        Ok(profile) => {
            ui.set_import_valid(true);
            ui.set_import_summary(
                format!(
                    "Конфигурация корректна · прокси: {} · правил: {}",
                    profile.proxies.len(),
                    profile.rules.len()
                )
                .into(),
            );
        }
        Err(error) => ui.set_import_error(format!("{error:#}").into()),
    }
}
fn clear(ui: &MainWindow, document: &RefCell<Document>, timer: &slint::Timer) {
    timer.stop();
    *document.borrow_mut() = Document::default();
    ui.set_import_json("".into());
    ui.set_import_lines(model(vec![]));
    ui.set_import_error("".into());
    ui.set_import_valid(false);
}
type CopyText = Rc<dyn Fn(&MainWindow, &str) -> Result<()>>;

pub fn wire(
    ui: &MainWindow,
    state: State,
    path: PathBuf,
    statuses: Arc<Mutex<proxies::Statuses>>,
    preview: bool,
) {
    wire_copy(
        ui,
        state,
        path,
        statuses,
        Rc::new(move |ui, text| {
            anyhow::ensure!(
                !preview,
                "В режиме проверки UI системный буфер обмена не изменяется"
            );
            #[cfg(windows)]
            {
                true_proxy::platform::windows::clipboard::copy(
                    super::appearance::native_handle(ui)? as usize,
                    text,
                )
            }
            #[cfg(not(windows))]
            {
                let _ = (ui, text);
                anyhow::bail!("Системный буфер обмена пока поддерживается только в Windows")
            }
        }),
    );
}
fn wire_copy(
    ui: &MainWindow,
    state: State,
    path: PathBuf,
    statuses: Arc<Mutex<proxies::Statuses>>,
    copy: CopyText,
) {
    let document = Rc::new(RefCell::new(Document::default()));
    let timer = Rc::new(slint::Timer::default());
    let toast = Rc::new(slint::Timer::default());
    let weak = ui.as_weak();
    let export_state = state.clone();
    ui.on_export_config(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_toast("".into());
            let result = (|| {
                let json = Profile::export(&export_state.borrow())?;
                copy(&ui, &json)?;
                ui.set_notice("".into());
                ui.set_toast("Конфигурация скопирована в буфер обмена".into());
                let weak = ui.as_weak();
                toast.start(
                    slint::TimerMode::SingleShot,
                    Duration::from_secs(4),
                    move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_toast("".into());
                        }
                    },
                );
                Ok(())
            })();
            report(&ui, result);
        }
    });
    let weak = ui.as_weak();
    let open_document = document.clone();
    let open_timer = timer.clone();
    ui.on_open_import(move || {
        if let Some(ui) = weak.upgrade() {
            clear(&ui, &open_document, &open_timer);
            ui.set_import_first_line(0);
            ui.set_import_visible_lines(40);
            ui.set_import_summary("Вставьте JSON конфигурации для проверки.".into());
            ui.set_dialog(3);
        }
    });
    let weak = ui.as_weak();
    let cancel_document = document.clone();
    let cancel_timer = timer.clone();
    ui.on_cancel_import(move || {
        if let Some(ui) = weak.upgrade() {
            clear(&ui, &cancel_document, &cancel_timer);
            ui.set_dialog(0);
        }
    });
    let weak = ui.as_weak();
    let edit_document = document.clone();
    let edit_timer = timer.clone();
    ui.on_import_edited(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_import_valid(false);
            ui.set_import_error("".into());
            ui.set_import_summary("Проверяем конфигурацию…".into());
            ui.set_import_lines(model(vec![]));
            let weak = ui.as_weak();
            let document = edit_document.clone();
            edit_timer.start(
                slint::TimerMode::SingleShot,
                Duration::from_millis(180),
                move || {
                    if let Some(ui) = weak.upgrade()
                        && ui.get_dialog() == 3
                    {
                        validate(&ui, &document);
                    }
                },
            );
        }
    });
    let weak = ui.as_weak();
    let view_document = document.clone();
    ui.on_import_viewport(move || {
        if let Some(ui) = weak.upgrade() {
            paint(&ui, &view_document.borrow());
        }
    });
    let weak = ui.as_weak();
    let format_document = document.clone();
    let format_timer = timer.clone();
    ui.on_format_import(move || {
        if let Some(ui) = weak.upgrade() {
            format_timer.stop();
            match Profile::parse(&ui.get_import_json()).and_then(|profile| profile.pretty()) {
                Ok(text) => {
                    ui.set_import_json(text.into());
                    validate(&ui, &format_document);
                }
                Err(_) => validate(&ui, &format_document),
            }
        }
    });
    let weak = ui.as_weak();
    ui.on_save_import(move || {
        if let Some(ui) = weak.upgrade() {
            timer.stop();
            validate(&ui, &document);
            // Parse again at commit time; a stale validation flag cannot authorize a save.
            let result = (|| -> Result<()> {
                let imported = Profile::parse(&ui.get_import_json())?;
                pending::persist(&ui, &state, &path, &statuses.lock().unwrap(), |config| {
                    imported.apply(config)
                })?;
                statuses
                    .lock()
                    .unwrap()
                    .retain(|id, _| state.borrow().proxies.iter().any(|proxy| &proxy.id == id));
                clear(&ui, &document, &timer);
                ui.set_dialog(0);
                Ok(())
            })();
            if let Err(error) = result {
                ui.set_import_error(format!("{error:#}").into());
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use i_slint_backend_testing::ElementHandle;
    use slint::Model;
    use std::sync::mpsc;
    use true_proxy::config::Config;
    fn click(ui: &MainWindow, label: &str) {
        ElementHandle::find_by_accessible_label(ui, label)
            .next()
            .unwrap()
            .mock_single_click(slint::platform::PointerEventButton::Left);
    }
    fn window() -> MainWindow {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1120., 780.));
        ui.set_page(4);
        ui.show().unwrap();
        ui
    }
    fn validate_now(ui: &MainWindow, text: &str) {
        ui.set_import_json(text.into());
        ui.invoke_import_edited();
        i_slint_backend_testing::mock_elapsed_time(Duration::from_millis(200));
        slint::platform::update_timers_and_animations();
    }
    #[test]
    fn export_copies_portable_json_and_toast_only_follows_success() {
        let ui = window();
        let copied = Rc::new(RefCell::new(String::new()));
        let output = copied.clone();
        wire_copy(
            &ui,
            Rc::new(RefCell::new(Config::default())),
            PathBuf::new(),
            Arc::default(),
            Rc::new(move |_, text| {
                *output.borrow_mut() = text.into();
                Ok(())
            }),
        );
        click(&ui, "Экспортировать");
        assert!(Profile::parse(&copied.borrow()).is_ok());
        assert!(ui.get_toast().contains("скопирована"));
        i_slint_backend_testing::mock_elapsed_time(Duration::from_secs(5));
        slint::platform::update_timers_and_animations();
        assert!(ui.get_toast().is_empty());
        wire_copy(
            &ui,
            Rc::new(RefCell::new(Config::default())),
            PathBuf::new(),
            Arc::default(),
            Rc::new(|_, _| anyhow::bail!("Clipboard busy")),
        );
        click(&ui, "Экспортировать");
        assert!(ui.get_toast().is_empty() && ui.get_notice().contains("Clipboard busy"));
    }
    #[test]
    fn import_validates_edits_rechecks_on_commit_and_defers_the_whole_profile() {
        let ui = window();
        let state = Rc::new(RefCell::new(Config::default()));
        let folder = std::env::temp_dir().join(format!("true-proxy-import-{}", std::process::id()));
        let path = folder.join("config.json");
        state.borrow().save(&path).unwrap();
        let (sender, commands) = mpsc::sync_channel(1);
        pending::wire(&ui, state.clone(), sender);
        wire_copy(
            &ui,
            state.clone(),
            path.clone(),
            Arc::default(),
            Rc::new(|_, _| Ok(())),
        );
        click(&ui, "Импортировать");
        assert_eq!(ui.get_dialog(), 3);
        let valid = r#"{"version":2,"proxies":[{"id":"new","name":"New VPN","host":"127.0.0.1","port":1081}],"rules":[],"default_action":{"kind":"proxy","proxy_id":"new"}}"#;
        validate_now(&ui, valid);
        assert!(ui.get_import_valid(), "{}", ui.get_import_error());
        click(&ui, "JSON конфигурации");
        ui.window()
            .dispatch_event(slint::platform::WindowEvent::KeyPressed { text: " ".into() });
        assert!(
            !ui.get_import_valid(),
            "Editing invalidates the previous validation immediately"
        );
        validate_now(&ui, valid);
        click(&ui, "Форматировать");
        assert!(ui.get_import_json().contains('\n') && ui.get_import_lines().row_count() > 1);
        // A click on a painted glyph must reach the native input, not the color layer.
        let editor = ElementHandle::find_by_accessible_label(&ui, "JSON конфигурации")
            .next()
            .unwrap();
        click(&ui, "JSON конфигурации");
        ui.window()
            .dispatch_event(slint::platform::WindowEvent::KeyPressed { text: " ".into() });
        i_slint_backend_testing::mock_elapsed_time(Duration::from_millis(200));
        slint::platform::update_timers_and_animations();
        let point = slint::LogicalPosition::new(
            editor.absolute_position().x + 1.,
            editor.absolute_position().y + 4.,
        );
        for event in [
            slint::platform::WindowEvent::PointerMoved { position: point },
            slint::platform::WindowEvent::PointerPressed {
                position: point,
                button: slint::platform::PointerEventButton::Left,
            },
            slint::platform::WindowEvent::PointerReleased {
                position: point,
                button: slint::platform::PointerEventButton::Left,
            },
        ] {
            ui.window().dispatch_event(event);
        }
        ui.window()
            .dispatch_event(slint::platform::WindowEvent::KeyPressed { text: "X".into() });
        assert!(
            ui.get_import_json().starts_with('X'),
            "Coloring must not block cursor positioning"
        );
        validate_now(&ui, valid);
        ui.set_import_json("{".into());
        click(&ui, "Сохранить");
        assert_eq!(ui.get_dialog(), 3);
        assert!(state.borrow().proxies.is_empty());
        assert!(ui.get_import_error().contains("строка"));
        validate_now(&ui, valid);
        ui.set_active(true);
        click(&ui, "Сохранить");
        assert_eq!(ui.get_dialog(), 0);
        assert!(ui.get_routing_pending() && ui.get_restart_prompt() && ui.get_active());
        assert_eq!(Config::load(&path).unwrap().proxies[0].port, 1081);
        assert!(state.borrow().routing_enabled && commands.try_recv().is_err());
        click(&ui, "Применить позже");
        assert!(ui.get_routing_pending());
        assert!(ui.get_import_json().is_empty() && ui.get_import_lines().row_count() == 0);
        click(&ui, "Импортировать");
        validate_now(&ui, "{broken}");
        click(&ui, "Отмена");
        assert_eq!(ui.get_dialog(), 0);
        assert_eq!(Config::load(&path).unwrap().proxies[0].port, 1081);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(folder).unwrap();
    }
    #[test]
    fn coloring_is_limited_to_the_visible_lines_and_cancel_stops_validation() {
        let ui = window();
        wire_copy(
            &ui,
            Rc::new(RefCell::new(Config::default())),
            PathBuf::new(),
            Arc::default(),
            Rc::new(|_, _| Ok(())),
        );
        click(&ui, "Импортировать");
        validate_now(&ui, &"  \"key\": true,\n".repeat(2000));
        let scroll = ElementHandle::find_by_element_id(&ui, "JsonEditor::scroll")
            .next()
            .unwrap();
        scroll.scroll(0., -10000.);
        i_slint_backend_testing::mock_elapsed_time(Duration::from_secs(1));
        slint::platform::update_timers_and_animations();
        assert!(
            ui.get_import_first_line() > 0,
            "Wheel scrolling must update the highlighted viewport"
        );
        assert_eq!(
            ui.get_import_lines().row_data(0).unwrap().number,
            ui.get_import_first_line()
        );
        ui.set_import_first_line(1000);
        ui.set_import_visible_lines(30);
        ui.invoke_import_viewport();
        assert!(ui.get_import_lines().row_count() <= 30);
        assert_eq!(ui.get_import_lines().row_data(0).unwrap().number, 1000);
        validate_now(&ui, &" ".repeat(9000));
        assert_eq!(
            ui.get_import_lines().row_count(),
            0,
            "Long unformatted lines must fall back to native text without stale highlights"
        );
        ui.set_import_json("{".into());
        ui.invoke_import_edited();
        click(&ui, "Отмена");
        i_slint_backend_testing::mock_elapsed_time(Duration::from_secs(1));
        slint::platform::update_timers_and_animations();
        assert!(ui.get_import_json().is_empty() && ui.get_import_lines().row_count() == 0);
    }
}
