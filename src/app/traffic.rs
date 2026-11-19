use super::bytes;
use crate::{MainWindow, TrafficReading};
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    fmt::Write,
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
    rendered_at: Cell<Option<Instant>>,
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
        let now = Instant::now();
        self.rendered_at.set(Some(now));
        let upload = chart_path(&history, now, scale, |point| point.upload);
        let download = chart_path(&history, now, scale, |point| point.download);
        ui.set_upload_area(upload.area.into());
        ui.set_download_area(download.area.into());
        ui.set_upload_path(upload.line.into());
        ui.set_download_path(download.line.into());
        ui.set_traffic_scale(super::model(
            (0..4)
                .map(|i| format!("{}/s", bytes(scale / 3 * (3 - i))).into())
                .collect(),
        ));
    }

    pub(super) fn reading(&self, seconds_ago: i32) -> TrafficReading {
        let Some(now) = self.rendered_at.get() else {
            return TrafficReading::default();
        };
        if !(0..=RETENTION.as_secs() as i32).contains(&seconds_ago) {
            return TrafficReading::default();
        }
        let target = Duration::from_secs(seconds_ago as u64);
        let history = self.history.borrow();
        let Some(point) = history
            .iter()
            .min_by_key(|point| now.saturating_duration_since(point.at).abs_diff(target))
        else {
            return TrafficReading::default();
        };
        let age = now.saturating_duration_since(point.at);
        // The cursor may be in a gap left by a suspended or hidden window.
        if age > RETENTION || age.abs_diff(target) > Duration::from_millis(1500) {
            return TrafficReading::default();
        }
        TrafficReading {
            valid: true,
            position: 1.0 - age.as_secs_f32() / RETENTION.as_secs_f32(),
            seconds_ago: age.as_secs_f32().round() as i32,
            download: format!("{}/s", bytes(point.download)).into(),
            upload: format!("{}/s", bytes(point.upload)).into(),
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

#[derive(Default)]
struct ChartPath {
    line: String,
    area: String,
}

fn chart_path(
    history: &VecDeque<Point>,
    now: Instant,
    scale: u64,
    rate: impl Fn(&Point) -> u64,
) -> ChartPath {
    let mut path = ChartPath::default();
    if history.len() < 2 {
        return path;
    }
    let x = |p: &Point| {
        let age = now.saturating_duration_since(p.at).as_secs_f64();
        600.0 * (1.0 - age / RETENTION.as_secs_f64())
    };
    let y = |p: &Point| 100.0 * (1.0 - rate(p) as f64 / scale as f64);
    let mut visible = history
        .iter()
        .skip_while(|p| now.saturating_duration_since(p.at) > RETENTION)
        .peekable();
    while let Some(first) = visible.next() {
        let start = path.line.len();
        let mut last = first;
        let _ = write!(path.line, "M{:.2} {:.2} ", x(first), y(first));
        while let Some(next) =
            visible.next_if(|p| p.at.saturating_duration_since(last.at) <= Duration::from_secs(3))
        {
            let _ = write!(path.line, "L{:.2} {:.2} ", x(next), y(next));
            last = next;
        }
        // Close each visible segment at its own baseline so a gap stays empty.
        path.area.push_str(&path.line[start..]);
        let _ = write!(path.area, "L{:.2} 100 L{:.2} 100 Z ", x(last), x(first));
    }
    path
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
        ui.set_proxies(ModelRc::new(VecModel::from(vec![crate::ProxyRow {
            name: "Test proxy".into(),
            address: "[2001:db8::1234]:1080".into(),
            ..Default::default()
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
        click(
            "Copy endpoint [2001:db8::1234]:1080",
            AccessibleRole::Button,
        );
        ui.set_dialog(3);
        click("Paste JSON", AccessibleRole::Button);
        assert_eq!(ui.get_import_json().as_str(), "[2001:db8::1234]:1080");
        ui.set_dialog(0);
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
        let path = chart_path(&points, make(20).at, scale, |point| point.download);
        assert_eq!(
            path.line.matches('M').count(),
            2,
            "hidden intervals must not be interpolated"
        );
        assert_eq!(path.area.matches('Z').count(), 2);
        traffic.rendered_at.set(Some(make(20).at));
        assert!(!traffic.reading(10).valid);
        assert_eq!(traffic.reading(19).download.as_str(), "200 B/s");
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
