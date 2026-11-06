use crate::{MainWindow, TechnicalLogs};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use slint::ComponentHandle;
use std::{
    cell::RefCell,
    fmt::Write as _,
    fs::{self, File},
    io::{ErrorKind, Read, Write as _},
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
};
use true_proxy::{
    engine::{LogEntry, LogLevel, LogSource, Statistics},
    platform,
};

#[derive(Default, Deserialize, Serialize)]
struct Preferences {
    recording: bool,
}

impl Preferences {
    fn load(path: &Path) -> Result<Self> {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error.into()),
        };
        let mut contents = Vec::new();
        file.take(4097).read_to_end(&mut contents)?;
        ensure!(contents.len() <= 4096, "Log preferences exceed 4 KiB");
        serde_json::from_slice(&contents).context("Could not read log preferences")
    }

    fn save(&self, path: &Path) -> Result<()> {
        fs::create_dir_all(path.parent().context("Missing log preferences directory")?)?;
        let temporary = path.with_extension("tmp");
        let mut file = File::create(&temporary)?;
        file.write_all(&serde_json::to_vec(self)?)?;
        file.sync_all()?;
        drop(file);
        platform::replace_file(&temporary, path).context("Could not save log preferences")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Filters {
    verbose: bool,
    errors_only: bool,
    source: Option<LogSource>,
}

impl Filters {
    fn read(logs: &TechnicalLogs<'_>) -> Self {
        Self {
            verbose: logs.get_verbosity() == 1,
            errors_only: logs.get_errors_only(),
            source: match logs.get_source() {
                1 => Some(LogSource::Backend),
                2 => Some(LogSource::Connections),
                _ => None,
            },
        }
    }

    fn accepts(self, entry: &LogEntry) -> bool {
        self.source.is_none_or(|source| source == entry.source)
            && if self.errors_only {
                entry.level == LogLevel::Error
            } else {
                self.verbose || entry.level != LogLevel::Verbose
            }
    }
}

#[derive(Default)]
struct Rendered {
    snapshot: Option<(u64, Filters)>,
    sequences: Vec<u64>,
}

#[derive(Default)]
pub(super) struct LogView {
    rendered: RefCell<Rendered>,
}

impl LogView {
    pub(super) fn render(&self, ui: &MainWindow, statistics: &Statistics) {
        if ui.get_page() != 5 || !ui.window().is_visible() || ui.window().is_minimized() {
            return;
        }
        let logs = ui.global::<TechnicalLogs>();
        let filters = Filters::read(&logs);
        let mut rendered = self.rendered.borrow_mut();
        let previous_revision = rendered
            .snapshot
            .filter(|(_, previous_filters)| *previous_filters == filters)
            .map(|(revision, _)| revision);
        let Some((revision, entries)) = statistics.log_snapshot(previous_revision) else {
            return;
        };
        rendered.snapshot = Some((revision, filters));
        logs.set_total(entries.len() as i32);
        let visible: Vec<_> = entries
            .iter()
            .filter(|entry| filters.accepts(entry))
            .collect();
        let sequences: Vec<_> = visible.iter().map(|entry| entry.sequence).collect();
        if sequences == rendered.sequences {
            return;
        }
        let mut text = String::new();
        for entry in visible {
            if !text.is_empty() {
                text.push('\n');
            }
            append_line(&mut text, entry);
        }
        logs.set_visible_count(sequences.len() as i32);
        logs.set_text(text.into());
        rendered.sequences = sequences;
    }
}

fn append_line(text: &mut String, entry: &LogEntry) {
    let source = match entry.source {
        LogSource::Backend => "Backend",
        LogSource::Connections => "Connections",
    };
    let level = match entry.level {
        LogLevel::Info => "INF",
        LogLevel::Verbose => "VRB",
        LogLevel::Error => "ERR",
    };
    if let Some((hour, minute, second)) = entry.time {
        write!(text, "{hour:02}:{minute:02}:{second:02}").unwrap();
    } else {
        text.push_str("—       ");
    }
    write!(text, "  {level}  [{source}]").unwrap();
    let mut separator = " ";
    for part in [
        &entry.process,
        &entry.destination,
        &entry.route,
        &entry.message,
    ] {
        if !part.is_empty() {
            text.push_str(separator);
            text.push_str(part);
            separator = " · ";
        }
    }
}

pub(super) fn wire(
    ui: &MainWindow,
    statistics: Arc<Statistics>,
    preferences_path: Option<PathBuf>,
    preview_recording: bool,
) -> Rc<LogView> {
    let view = Rc::new(LogView::default());
    let logs = ui.global::<TechnicalLogs>();
    let recording = match preferences_path.as_deref() {
        Some(path) => match Preferences::load(path) {
            Ok(preferences) => preferences.recording,
            Err(error) => {
                super::report(ui, Err(error.context("Could not load log settings")));
                false
            }
        },
        None => preview_recording,
    };
    statistics.set_log_tracking(recording);
    logs.set_recording(recording);

    let weak = ui.as_weak();
    let stats = statistics.clone();
    logs.on_set_recording(move |recording| {
        let Some(ui) = weak.upgrade() else { return };
        if let Some(path) = &preferences_path
            && let Err(error) = (Preferences { recording }).save(path)
        {
            super::report(&ui, Err(error));
            return;
        }
        stats.set_log_tracking(recording);
        ui.global::<TechnicalLogs>().set_recording(recording);
    });
    let weak = ui.as_weak();
    let stats = statistics.clone();
    let render = view.clone();
    logs.on_clear(move || {
        stats.clear();
        if let Some(ui) = weak.upgrade() {
            render.render(&ui, &stats);
        }
    });
    let render = view.clone();
    let weak = ui.as_weak();
    logs.on_filter(move || {
        if let Some(ui) = weak.upgrade() {
            render.render(&ui, &statistics);
        }
    });
    view
}

#[cfg(test)]
mod tests {
    use super::*;
    use i_slint_backend_testing::ElementHandle;
    use slint::platform::{Key, PointerEventButton, WindowEvent};

    fn click(ui: &MainWindow, label: &str) {
        ElementHandle::find_by_accessible_label(ui, label)
            .next()
            .unwrap_or_else(|| panic!("Missing control: {label}"))
            .mock_single_click(PointerEventButton::Left);
    }

    #[test]
    fn log_filters_and_native_multiline_copy_preserve_a_live_selection() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(960., 640.));
        ui.set_page(5);
        ui.show().unwrap();
        let statistics = Arc::new(Statistics::default());
        let view = wire(&ui, statistics.clone(), None, true);
        let logs = ui.global::<TechnicalLogs>();
        assert!(!logs.get_follow());

        statistics.log(LogSource::Backend, LogLevel::Info, "", "", "", "Started");
        view.render(&ui, &statistics);
        let original = logs.get_text();
        assert_eq!(logs.get_visible_count(), 1);
        statistics.log(LogSource::Connections, LogLevel::Verbose, "", "", "", "DNS");
        view.render(&ui, &statistics);
        assert_eq!(logs.get_text(), original);
        assert_eq!(logs.get_total(), 2);
        statistics.log(LogSource::Backend, LogLevel::Error, "", "", "", "Failure");
        view.render(&ui, &statistics);
        assert_eq!(logs.get_visible_count(), 2);
        let selected = logs.get_text();
        assert!(selected.contains("[Backend] Started\n"));
        assert!(selected.ends_with("ERR  [Backend] Failure"));
        i_slint_backend_testing::mock_elapsed_time(std::time::Duration::ZERO);
        click(&ui, "Log text");
        let window = ui.window();
        let ctrl = Key::Control.into();
        window.dispatch_event(WindowEvent::KeyPressed { text: ctrl });
        window.dispatch_event(WindowEvent::KeyPressed { text: "a".into() });
        for _ in 0..256 {
            statistics.log(LogSource::Backend, LogLevel::Info, "", "", "", "Later");
        }
        view.render(&ui, &statistics);
        assert!(!logs.get_text().contains("Started"));
        i_slint_backend_testing::mock_elapsed_time(std::time::Duration::ZERO);
        window.dispatch_event(WindowEvent::KeyPressed { text: "c".into() });
        window.dispatch_event(WindowEvent::KeyReleased {
            text: Key::Control.into(),
        });
        ui.set_dialog(3);
        click(&ui, "Paste JSON");
        assert_eq!(ui.get_import_json(), selected);
        ui.set_dialog(0);

        statistics.log(LogSource::Connections, LogLevel::Verbose, "", "", "", "DNS");
        statistics.log(LogSource::Backend, LogLevel::Error, "", "", "", "Failure");
        logs.set_verbosity(1);
        logs.set_source(2);
        logs.invoke_filter();
        assert_eq!(logs.get_visible_count(), 1);
        assert!(logs.get_text().contains("VRB  [Connections] DNS"));
        logs.set_errors_only(true);
        logs.invoke_filter();
        assert!(logs.get_text().is_empty());
        logs.set_source(0);
        logs.invoke_filter();
        assert!(logs.get_text().contains("ERR  [Backend] Failure"));
    }

    #[test]
    fn start_pause_persists_and_clear_resets_visible_and_stored_logs() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.set_page(5);
        ui.show().unwrap();
        let path =
            std::env::temp_dir().join(format!("true-proxy-logs-{}.json", super::super::id()));
        let statistics = Arc::new(Statistics::default());
        let view = wire(&ui, statistics.clone(), Some(path.clone()), false);
        let logs = ui.global::<TechnicalLogs>();
        assert!(!logs.get_recording());
        click(&ui, "Start");
        assert!(logs.get_recording() && Preferences::load(&path).unwrap().recording);
        ui.set_page(0);
        statistics.log(LogSource::Backend, LogLevel::Info, "", "", "", "Background");
        ui.set_page(5);
        view.render(&ui, &statistics);
        assert!(logs.get_text().contains("Background"));
        click(&ui, "Pause");
        assert!(!logs.get_recording() && !Preferences::load(&path).unwrap().recording);
        statistics.log(LogSource::Backend, LogLevel::Info, "", "", "", "Paused");
        view.render(&ui, &statistics);
        assert_eq!(logs.get_total(), 1);
        click(&ui, "Clear");
        assert_eq!(logs.get_total(), 0);
        assert!(logs.get_text().is_empty());
        assert!(statistics.log_snapshot(None).unwrap().1.is_empty());
        fs::remove_file(path).unwrap();
    }
}
