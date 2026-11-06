use super::model;
use crate::{MainWindow, TechnicalLogRow, TechnicalLogs};
use slint::{ComponentHandle, Model, VecModel};
use std::{cell::RefCell, rc::Rc, sync::Arc};
use true_proxy::engine::{LogEntry, LogLevel, LogSource, Statistics};

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

        let previous = logs.get_rows();
        if let Some(drop) = retained_suffix(&rendered.sequences, &sequences)
            && let Some(rows) = previous
                .as_any()
                .downcast_ref::<VecModel<TechnicalLogRow>>()
        {
            for _ in 0..drop {
                rows.remove(0);
            }
            for entry in visible.into_iter().skip(rendered.sequences.len() - drop) {
                rows.push(row(entry));
            }
        } else {
            logs.set_rows(model(visible.into_iter().map(row).collect()));
        }
        rendered.sequences = sequences;
        logs.set_revision(logs.get_revision().wrapping_add(1));
    }
}

/// Existing rows form a suffix after ring eviction and a prefix before appending.
fn retained_suffix(previous: &[u64], current: &[u64]) -> Option<usize> {
    let first = current.first()?;
    let dropped = previous.iter().position(|sequence| sequence == first)?;
    current.starts_with(&previous[dropped..]).then_some(dropped)
}

fn row(entry: &LogEntry) -> TechnicalLogRow {
    let source = match entry.source {
        LogSource::Backend => "Backend",
        LogSource::Connections => "Connections",
    };
    let level = match entry.level {
        LogLevel::Info => "INF",
        LogLevel::Verbose => "VRB",
        LogLevel::Error => "ERR",
    };
    let details = [
        &entry.process,
        &entry.destination,
        &entry.route,
        &entry.message,
    ]
    .into_iter()
    .map(String::as_str)
    .filter(|part| !part.is_empty())
    .collect::<Vec<_>>()
    .join(" · ");
    TechnicalLogRow {
        time: entry
            .time
            .map(|(hour, minute, second)| format!("{hour:02}:{minute:02}:{second:02}"))
            .unwrap_or_else(|| "—".into())
            .into(),
        level: level.into(),
        message: format!("[{source}] {details}").into(),
        error: entry.level == LogLevel::Error,
    }
}

pub(super) fn wire(ui: &MainWindow, statistics: Arc<Statistics>) -> Rc<LogView> {
    let view = Rc::new(LogView::default());
    let render = view.clone();
    let weak = ui.as_weak();
    ui.global::<TechnicalLogs>().on_filter(move || {
        if let Some(ui) = weak.upgrade() {
            render.render(&ui, &statistics);
        }
    });
    view
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_filters_hide_verbose_entries_and_reuse_the_model_for_appends() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.set_page(5);
        ui.show().unwrap();
        let statistics = Arc::new(Statistics::default());
        let view = wire(&ui, statistics.clone());
        let logs = ui.global::<TechnicalLogs>();
        assert!(!logs.get_follow());

        statistics.log(LogSource::Backend, LogLevel::Info, "", "", "", "Started");
        view.render(&ui, &statistics);
        let original = logs.get_rows();
        assert_eq!(original.row_count(), 1);
        let revision = logs.get_revision();
        statistics.log(LogSource::Connections, LogLevel::Verbose, "", "", "", "DNS");
        view.render(&ui, &statistics);
        assert_eq!(logs.get_revision(), revision);
        assert_eq!(logs.get_total(), 2);
        statistics.log(LogSource::Backend, LogLevel::Error, "", "", "", "Failure");
        view.render(&ui, &statistics);
        assert_eq!(original.row_count(), 2);
        assert!(original.row_data(0).unwrap().message.contains("Started"));
        assert!(original.row_data(1).unwrap().error);

        logs.set_verbosity(1);
        logs.set_source(2);
        logs.invoke_filter();
        assert_eq!(logs.get_rows().row_count(), 1);
        assert_eq!(logs.get_rows().row_data(0).unwrap().level, "VRB");
        logs.set_errors_only(true);
        logs.invoke_filter();
        assert_eq!(logs.get_rows().row_count(), 0);
        logs.set_source(0);
        logs.invoke_filter();
        assert!(logs.get_rows().row_data(0).unwrap().error);
    }
}
