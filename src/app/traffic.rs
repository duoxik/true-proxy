use super::bytes;
use crate::MainWindow;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use true_proxy::engine::Statistics;

// Keep only two minutes of aggregated rates. Sampling follows the existing
// visible-window timer, for up to two minutes after leaving the Dashboard.
const MIN_SAMPLE_INTERVAL: Duration = Duration::from_millis(900);
const RETENTION: Duration = Duration::from_secs(120);
const MAX_POINTS: usize = 121;

#[derive(Clone, Copy)]
struct Sample {
    at: Instant,
    uploaded: u64,
    downloaded: u64,
}

#[derive(Clone, Copy)]
struct Point {
    at: Instant,
    upload: u64,
    download: u64,
}

#[derive(Default)]
pub(super) struct DashboardTraffic {
    previous: Cell<Option<Sample>>,
    last_dashboard: Cell<Option<Instant>>,
    history: RefCell<VecDeque<Point>>,
}

impl DashboardTraffic {
    pub(super) fn suspend(&self) {
        // Retain recent points, but never average a hidden interval into a rate.
        self.previous.set(None);
    }

    pub(super) fn observe(&self, statistics: &Statistics, dashboard: bool) -> bool {
        self.sample(
            Sample {
                at: Instant::now(),
                uploaded: statistics.uploaded.load(Ordering::Relaxed),
                downloaded: statistics.downloaded.load(Ordering::Relaxed),
            },
            dashboard,
        )
    }

    fn sample(&self, sample: Sample, dashboard: bool) -> bool {
        if dashboard {
            self.last_dashboard.set(Some(sample.at));
        }
        let recording = self
            .last_dashboard
            .get()
            .is_some_and(|last| sample.at.saturating_duration_since(last) < RETENTION);
        let mut history = self.history.borrow_mut();
        while history
            .front()
            .is_some_and(|point| sample.at.saturating_duration_since(point.at) > RETENTION)
        {
            history.pop_front();
        }
        if !recording {
            history.clear();
            self.suspend();
            return false;
        }
        if let Some((upload, download)) = self.rates(sample) {
            if history.len() == MAX_POINTS {
                history.pop_front();
            }
            history.push_back(Point {
                at: sample.at,
                upload,
                download,
            });
        }
        true
    }

    pub(super) fn render(&self, ui: &MainWindow, statistics: &Statistics) {
        let uploaded = statistics.uploaded.load(Ordering::Relaxed);
        let downloaded = statistics.downloaded.load(Ordering::Relaxed);
        ui.set_uploaded(bytes(uploaded).into());
        ui.set_downloaded(bytes(downloaded).into());
        let total = uploaded as f64 + downloaded as f64;
        ui.set_has_transfer(total > 0.0);
        ui.set_upload_share(if total > 0.0 {
            (uploaded as f64 / total) as f32
        } else {
            0.0
        });
        let history = self.history.borrow();
        if let Some(point) = history.back() {
            ui.set_upload_rate(format!("{}/s", bytes(point.upload)).into());
            ui.set_download_rate(format!("{}/s", bytes(point.download)).into());
        }
        let scale = chart_scale(&history);
        let (upload, download) = chart_paths(&history, Instant::now(), scale);
        ui.set_upload_path(upload.into());
        ui.set_download_path(download.into());
        ui.set_traffic_scale(super::model(
            (0..4)
                .map(|i| format!("{}/s", bytes(scale / 3 * (3 - i))).into())
                .collect(),
        ));
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
        // A restart resets counters; don't carry an old session into the chart.
        let per_second = |current: u64, previous| {
            (current.saturating_sub(previous) as f64 / elapsed.as_secs_f64()).round() as u64
        };
        Some((
            per_second(sample.uploaded, previous.uploaded),
            per_second(sample.downloaded, previous.downloaded),
        ))
    }
}

fn chart_scale(history: &VecDeque<Point>) -> u64 {
    let peak = history
        .iter()
        .map(|p| p.upload.max(p.download))
        .max()
        .unwrap_or(0)
        .max(3);
    let raw_step = peak.div_ceil(3);
    let power = 10_u64.pow(raw_step.ilog10());
    let step = [1, 2, 5, 10]
        .into_iter()
        .map(|n| power.saturating_mul(n))
        .find(|step| *step >= raw_step)
        .unwrap_or(raw_step);
    step.saturating_mul(3)
}

fn chart_paths(history: &VecDeque<Point>, now: Instant, scale: u64) -> (String, String) {
    use std::fmt::Write;
    if history.len() < 2 {
        return (String::new(), String::new());
    }
    let mut upload = String::new();
    let mut download = String::new();
    let mut previous = None::<Instant>;
    for point in history {
        let age = now.saturating_duration_since(point.at).as_secs_f64();
        if age > RETENTION.as_secs_f64() {
            continue;
        }
        let x = (1.0 - age / RETENTION.as_secs_f64()) * 600.0;
        let command = if previous
            .is_none_or(|at| point.at.saturating_duration_since(at) > Duration::from_secs(3))
        {
            'M'
        } else {
            'L'
        };
        previous = Some(point.at);
        let _ = write!(
            upload,
            "{command}{x:.2} {:.2} ",
            100.0 - point.upload as f64 / scale as f64 * 100.0
        );
        let _ = write!(
            download,
            "{command}{x:.2} {:.2} ",
            100.0 - point.download as f64 / scale as f64 * 100.0
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
    fn recent_history_survives_navigation_and_expires_with_bounded_storage() {
        let traffic = DashboardTraffic::default();
        let at = Instant::now();
        let make = |seconds| Sample {
            at: at + Duration::from_secs(seconds),
            uploaded: seconds * 100,
            downloaded: seconds * 200,
        };
        traffic.sample(make(0), true);
        traffic.sample(make(1), true);
        traffic.sample(make(2), false);
        assert_eq!(traffic.history.borrow().len(), 3);
        traffic.sample(make(3), true);
        assert_eq!(traffic.history.borrow().len(), 4);
        traffic.suspend();
        traffic.sample(make(20), true);
        assert_eq!(traffic.history.borrow().back().unwrap().download, 0);
        let points = traffic.history.borrow();
        let scale = chart_scale(&points);
        assert!(scale >= 200);
        let (_, path) = chart_paths(&points, make(20).at, scale);
        assert_eq!(
            path.matches('M').count(),
            2,
            "hidden intervals must not be interpolated"
        );
        drop(points);
        for seconds in 21..400 {
            traffic.sample(make(seconds), true);
        }
        assert!(traffic.history.borrow().len() <= MAX_POINTS);
        assert!(traffic.sample(make(400), false));
        assert!(!traffic.sample(make(521), false));
        assert!(traffic.history.borrow().is_empty());
        traffic.sample(make(522), true);
        assert_eq!(traffic.history.borrow().len(), 1);
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
        traffic.suspend();
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
