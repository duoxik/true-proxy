use super::bytes;
use crate::MainWindow;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use true_proxy::engine::Statistics;

// The one-second dashboard timer shares its callback with resize and focus events.
// Ignore early events without moving the sampling window.
const MIN_SAMPLE_INTERVAL: Duration = Duration::from_millis(900);

#[derive(Clone, Copy)]
struct Sample {
    at: Instant,
    uploaded: u64,
    downloaded: u64,
}

#[derive(Default)]
pub(super) struct DashboardTraffic {
    previous: Cell<Option<Sample>>,
    history: RefCell<VecDeque<(u64, u64)>>,
}

impl DashboardTraffic {
    pub(super) fn reset(&self) {
        self.previous.set(None);
        self.history.borrow_mut().clear();
    }

    pub(super) fn refresh(&self, ui: &MainWindow, statistics: &Statistics) {
        let sample = Sample {
            at: Instant::now(),
            uploaded: statistics.uploaded.load(Ordering::Relaxed),
            downloaded: statistics.downloaded.load(Ordering::Relaxed),
        };
        ui.set_uploaded(bytes(sample.uploaded).into());
        ui.set_downloaded(bytes(sample.downloaded).into());
        let total = sample.uploaded as f64 + sample.downloaded as f64;
        ui.set_has_transfer(total > 0.0);
        ui.set_upload_share(if total > 0.0 {
            (sample.uploaded as f64 / total) as f32
        } else {
            0.0
        });

        if let Some((upload, download)) = self.rates(sample) {
            ui.set_upload_rate(format!("{}/s", bytes(upload)).into());
            ui.set_download_rate(format!("{}/s", bytes(download)).into());
            let mut history = self.history.borrow_mut();
            if history.len() == 60 {
                history.pop_front();
            }
            history.push_back((upload, download));
            let (upload, download) = chart_paths(&history);
            ui.set_upload_path(upload.into());
            ui.set_download_path(download.into());
        }
    }

    fn rates(&self, sample: Sample) -> Option<(u64, u64)> {
        let Some(previous) = self.previous.get() else {
            self.previous.set(Some(sample));
            return Some((0, 0));
        };
        let elapsed = sample.at.saturating_duration_since(previous.at);
        if elapsed < MIN_SAMPLE_INTERVAL {
            return None;
        }
        self.previous.set(Some(sample));
        let per_second = |current: u64, previous| {
            (current.saturating_sub(previous) as f64 / elapsed.as_secs_f64()).round() as u64
        };
        Some((
            per_second(sample.uploaded, previous.uploaded),
            per_second(sample.downloaded, previous.downloaded),
        ))
    }
}

// Both series share a scale. Keep missing/hidden intervals out of the chart;
// refresh is driven only by the existing visible-dashboard timer.
fn chart_paths(history: &VecDeque<(u64, u64)>) -> (String, String) {
    use std::fmt::Write;
    if history.len() < 2 {
        return (String::new(), String::new());
    }
    let peak = history
        .iter()
        .map(|&(up, down)| up.max(down))
        .max()
        .unwrap_or(1)
        .max(1) as f64;
    let mut upload = String::new();
    let mut download = String::new();
    for (index, &(up, down)) in history.iter().enumerate() {
        let x = (60 - history.len() + index) as f64 * 600.0 / 59.0;
        let command = if index == 0 { 'M' } else { 'L' };
        let _ = write!(
            upload,
            "{command}{x:.2} {:.2} ",
            98.0 - up as f64 / peak * 90.0
        );
        let _ = write!(
            download,
            "{command}{x:.2} {:.2} ",
            98.0 - down as f64 / peak * 90.0
        );
    }
    (upload, download)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_controls_work_on_first_click_at_minimum_window_size() {
        use i_slint_backend_testing::{AccessibleRole, ElementHandle};
        use slint::{ComponentHandle, ModelRc, VecModel, platform::PointerEventButton};
        use std::rc::Rc;
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(960., 640.));
        ui.set_rules(ModelRc::new(VecModel::from(vec![crate::RuleRow {
            id: "apps".into(),
            name: "Applications".into(),
            route: "Proxy · VPN".into(),
            enabled: true,
            priority: 1,
        }])));
        let toggles = Rc::new(Cell::new(0));
        let count = toggles.clone();
        ui.on_toggle(move || count.set(count.get() + 1));
        let changed_rule = Rc::new(Cell::new(false));
        let changed = changed_rule.clone();
        ui.on_toggle_rule(move |id| changed.set(id == "apps"));
        ui.show().unwrap();
        let click = |label, role| {
            ElementHandle::find_by_accessible_label(&ui, label)
                .find(|element| element.accessible_role() == Some(role))
                .unwrap()
                .mock_single_click(PointerEventButton::Left);
        };
        click("Routing", AccessibleRole::Button);
        assert_eq!(toggles.get(), 1);
        ui.set_busy(true);
        click("Routing", AccessibleRole::Button);
        assert_eq!(toggles.get(), 1);
        ui.set_busy(false);
        click("Rule Applications", AccessibleRole::Switch);
        assert!(changed_rule.get());
        click("View Proxies", AccessibleRole::Button);
        assert_eq!(ui.get_page(), 2);
        ui.set_page(0);
        click("View Rules", AccessibleRole::Button);
        assert_eq!(ui.get_page(), 1);
    }

    #[test]
    fn chart_uses_shared_scale_and_requires_two_observations() {
        assert_eq!(
            chart_paths(&VecDeque::from([(0, 0)])),
            (String::new(), String::new())
        );
        let (up, down) = chart_paths(&VecDeque::from([(0, 100), (50, 0)]));
        assert!(up.ends_with("L600.00 53.00 "));
        assert!(down.ends_with("L600.00 98.00 "));
        assert!(down.contains(" 8.00 "));
        let traffic = DashboardTraffic::default();
        traffic.history.borrow_mut().push_back((1, 2));
        traffic.reset();
        assert!(traffic.history.borrow().is_empty());
    }

    #[test]
    fn rates_use_elapsed_time_and_ignore_early_callbacks() {
        let traffic = DashboardTraffic::default();
        let at = Instant::now();
        assert_eq!(
            traffic.rates(Sample {
                at,
                uploaded: 1024,
                downloaded: 4096,
            }),
            Some((0, 0))
        );
        assert_eq!(
            traffic.rates(Sample {
                at: at + Duration::from_millis(20),
                uploaded: 2048,
                downloaded: 5120,
            }),
            None
        );
        assert_eq!(
            traffic.rates(Sample {
                at: at + Duration::from_millis(1500),
                uploaded: 4096,
                downloaded: 10240,
            }),
            Some((2048, 4096))
        );
    }

    #[test]
    fn a_counter_reset_or_hidden_interval_does_not_report_a_burst() {
        let traffic = DashboardTraffic::default();
        let at = Instant::now();
        let sample = Sample {
            at,
            uploaded: 4096,
            downloaded: 4096,
        };
        assert_eq!(traffic.rates(sample), Some((0, 0)));
        assert_eq!(
            traffic.rates(Sample {
                at: at + Duration::from_secs(1),
                uploaded: 1024,
                downloaded: 4096,
            }),
            Some((0, 0))
        );
        traffic.reset();
        assert_eq!(
            traffic.rates(Sample {
                at: at + Duration::from_secs(30),
                uploaded: 1048576,
                downloaded: 1048576,
            }),
            Some((0, 0))
        );
    }
}
