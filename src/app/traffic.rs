use super::bytes;
use crate::MainWindow;
use std::{
    cell::Cell,
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
}

impl DashboardTraffic {
    pub(super) fn reset(&self) {
        self.previous.set(None);
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

#[cfg(test)]
mod tests {
    use super::*;

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
