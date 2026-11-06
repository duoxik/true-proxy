use crate::config::Config;
use anyhow::{Result, ensure};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const MAX_LOGS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogSource {
    Backend,
    Connections,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Verbose,
    Error,
}

#[derive(Clone)]
pub struct LogEntry {
    pub sequence: u64,
    pub time: Option<(u16, u16, u16)>,
    pub source: LogSource,
    pub level: LogLevel,
    pub process: String,
    pub destination: String,
    pub route: String,
    pub message: String,
}

#[derive(Default)]
struct LogBuffer {
    revision: u64,
    entries: VecDeque<LogEntry>,
}

#[derive(Default)]
pub struct Statistics {
    pub activity: Arc<crate::connections::Connections>,
    pub uploaded: AtomicU64,
    pub downloaded: AtomicU64,
    pub connections: AtomicU64,
    pub blocked: AtomicU64,
    log_tracking: AtomicBool,
    logs: Mutex<LogBuffer>,
    processes: Mutex<HashMap<String, Arc<ProcessCounters>>>,
    routing_started: Mutex<Option<Instant>>,
}

#[derive(Default)]
pub struct ProcessCounters {
    pub name: String,
    pub active: AtomicU64,
    pub uploaded: AtomicU64,
    pub downloaded: AtomicU64,
}

pub struct ProcessSnapshot {
    pub name: String,
    pub active: u64,
    pub uploaded: u64,
    pub downloaded: u64,
}

pub struct ConnectionGuard {
    statistics: Arc<Statistics>,
    pub process: Arc<ProcessCounters>,
}
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.statistics.connections.fetch_sub(1, Ordering::Relaxed);
        self.process.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Statistics {
    pub fn routing_active(&self, active: bool) {
        if !active {
            self.activity.finish_all("Routing stopped");
        }
        let mut started = self.routing_started.lock().unwrap();
        let changed = started.is_some() != active;
        *started = active.then(Instant::now);
        drop(started);
        if changed {
            let message = if active {
                "Routing started"
            } else {
                "Routing stopped"
            };
            self.log(LogSource::Backend, LogLevel::Info, "", "", "", message);
        }
    }
    pub fn uptime(&self) -> Duration {
        self.routing_started
            .lock()
            .unwrap()
            .map_or(Duration::ZERO, |start| start.elapsed())
    }
    pub fn process(&self, name: &str) -> Arc<ProcessCounters> {
        let mut processes = self
            .processes
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut key = name.to_lowercase();
        let mut label = name;
        if !processes.contains_key(&key) && processes.len() >= 511 {
            key = "\0other".into();
            label = "Other processes";
        }
        processes
            .entry(key)
            .or_insert_with(|| {
                Arc::new(ProcessCounters {
                    name: label.to_string(),
                    ..Default::default()
                })
            })
            .clone()
    }
    pub fn connection(self: &Arc<Self>, name: &str) -> ConnectionGuard {
        let process = self.process(name);
        process.active.fetch_add(1, Ordering::Relaxed);
        self.connections.fetch_add(1, Ordering::Relaxed);
        ConnectionGuard {
            statistics: self.clone(),
            process,
        }
    }
    pub fn process_snapshots(&self) -> Vec<ProcessSnapshot> {
        self.processes
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .values()
            .map(|process| ProcessSnapshot {
                name: process.name.clone(),
                active: process.active.load(Ordering::Relaxed),
                uploaded: process.uploaded.load(Ordering::Relaxed),
                downloaded: process.downloaded.load(Ordering::Relaxed),
            })
            .collect()
    }
    pub fn log(
        &self,
        source: LogSource,
        level: LogLevel,
        process: impl Into<String>,
        destination: impl Into<String>,
        route: impl Into<String>,
        message: impl Into<String>,
    ) {
        let mut entry = LogEntry {
            sequence: 0,
            time: crate::platform::local_clock(),
            source,
            level,
            process: process.into(),
            destination: destination.into(),
            route: route.into(),
            message: message.into(),
        };
        let mut logs = self.logs.lock().unwrap_or_else(|e| e.into_inner());
        logs.revision = logs.revision.wrapping_add(1);
        entry.sequence = logs.revision;
        if logs.entries.len() == MAX_LOGS {
            logs.entries.pop_front();
        }
        logs.entries.push_back(entry);
    }
    /// Detailed connection events may feed the visible log without tracking sessions.
    pub fn set_log_tracking(&self, enabled: bool) {
        self.log_tracking.store(enabled, Ordering::Relaxed);
    }
    pub fn log_tracking(&self) -> bool {
        self.log_tracking.load(Ordering::Relaxed)
    }
    pub fn log_snapshot(&self, previous: Option<u64>) -> Option<(u64, Vec<LogEntry>)> {
        let logs = self.logs.lock().unwrap_or_else(|e| e.into_inner());
        (previous != Some(logs.revision))
            .then(|| (logs.revision, logs.entries.iter().cloned().collect()))
    }
    pub fn clear(&self) {
        let mut logs = self.logs.lock().unwrap_or_else(|e| e.into_inner());
        if !logs.entries.is_empty() {
            logs.entries.clear();
            logs.revision = logs.revision.wrapping_add(1);
        }
    }
}

pub type FailureHandler = Arc<dyn Fn(String) + Send + Sync>;

#[cfg(windows)]
pub struct Engine {
    inner: crate::platform::windows::network::Network,
}
#[cfg(not(windows))]
pub struct Engine;

impl Engine {
    pub fn start(
        config: Config,
        statistics: Arc<Statistics>,
        failure: FailureHandler,
    ) -> Result<Self> {
        config.validate()?;
        ensure!(
            !config.proxies.is_empty(),
            "Add a SOCKS5 proxy and an application rule"
        );
        #[cfg(windows)]
        {
            ensure!(
                crate::platform::is_admin(),
                "Traffic interception requires administrator rights. Run True Proxy as administrator."
            );
            Ok(Self {
                inner: crate::platform::windows::network::Network::start(
                    config, statistics, failure,
                )?,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (statistics, failure);
            anyhow::bail!("Traffic interception is currently available only on Windows");
        }
    }
    pub fn stop(self) {
        drop(self);
    }
}

#[cfg(windows)]
impl Drop for Engine {
    fn drop(&mut self) {
        self.inner.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn session_uptime_uses_start_instant_and_resets_at_stop() {
        let stats = Statistics::default();
        assert_eq!(stats.uptime(), Duration::ZERO);
        *stats.routing_started.lock().unwrap() = Some(Instant::now() - Duration::from_secs(3723));
        assert_eq!(stats.uptime().as_secs(), 3723);
        stats.routing_active(false);
        assert_eq!(stats.uptime(), Duration::ZERO);
        stats.routing_active(true);
        assert!(stats.uptime() < Duration::from_secs(1));
    }
    #[test]
    fn per_process_live_counts_survive_log_clear_and_end_on_drop() {
        let stats = Arc::new(Statistics::default());
        let a = stats.connection("Discord.exe");
        let b = stats.connection("discord.exe");
        a.process.uploaded.store(123, Ordering::Relaxed);
        stats.log(
            LogSource::Connections,
            LogLevel::Info,
            "Discord.exe",
            "test",
            "proxy",
            "TCP",
        );
        stats.clear();
        let rows = stats.process_snapshots();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].active, 2);
        assert_eq!(rows[0].uploaded, 123);
        drop((a, b));
        assert_eq!(stats.connections.load(Ordering::Relaxed), 0);
        assert_eq!(stats.process_snapshots()[0].active, 0);
    }
    #[test]
    fn technical_logs_are_bounded_and_return_only_changed_snapshots() {
        let stats = Statistics::default();
        for index in 0..=MAX_LOGS {
            stats.log(
                LogSource::Backend,
                LogLevel::Error,
                "",
                "",
                "",
                index.to_string(),
            );
        }
        let (revision, entries) = stats.log_snapshot(None).unwrap();
        assert_eq!(entries.len(), MAX_LOGS);
        assert_eq!(entries[0].message, "1");
        assert_eq!(entries[MAX_LOGS - 1].message, MAX_LOGS.to_string());
        assert!(stats.log_snapshot(Some(revision)).is_none());
        stats.clear();
        assert!(stats.log_snapshot(Some(revision)).unwrap().1.is_empty());
    }
    #[test]
    fn process_metrics_are_bounded() {
        let stats = Statistics::default();
        for i in 0..2000 {
            stats.process(&format!("app-{i}.exe"));
        }
        assert_eq!(stats.process_snapshots().len(), 512);
    }
}
