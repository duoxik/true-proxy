use crate::config::Config;
use anyhow::{Result, ensure};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct LogEntry {
    pub sequence: u64,
    pub process: String,
    pub destination: String,
    pub route: String,
    pub message: String,
}

#[derive(Default)]
pub struct Statistics {
    pub activity: Arc<crate::connections::Connections>,
    pub uploaded: AtomicU64,
    pub downloaded: AtomicU64,
    pub connections: AtomicU64,
    pub blocked: AtomicU64,
    sequence: AtomicU64,
    logs: Mutex<VecDeque<LogEntry>>,
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
            self.activity.finish_all("Маршрутизация остановлена");
        }
        *self.routing_started.lock().unwrap() = active.then(Instant::now);
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
            label = "Другие процессы";
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
        process: impl Into<String>,
        destination: impl Into<String>,
        route: impl Into<String>,
        message: impl Into<String>,
    ) {
        let entry = LogEntry {
            sequence: self.sequence.fetch_add(1, Ordering::Relaxed),
            process: process.into(),
            destination: destination.into(),
            route: route.into(),
            message: message.into(),
        };
        let mut logs = self.logs.lock().unwrap_or_else(|e| e.into_inner());
        if logs.len() >= 256 {
            logs.pop_front();
        }
        logs.push_back(entry);
    }
    pub fn logs(&self) -> Vec<LogEntry> {
        self.logs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .rev()
            .cloned()
            .collect()
    }
    pub fn clear(&self) {
        self.logs.lock().unwrap_or_else(|e| e.into_inner()).clear();
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
            "Добавьте SOCKS5-прокси и правило для приложения"
        );
        #[cfg(windows)]
        {
            ensure!(
                crate::platform::is_admin(),
                "Перехвату нужны права администратора. Запустите True Proxy с повышенными правами."
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
            anyhow::bail!("Перехват трафика пока реализован только для Windows");
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
        stats.log("Discord.exe", "test", "proxy", "TCP");
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
    fn process_metrics_are_bounded() {
        let stats = Statistics::default();
        for i in 0..2000 {
            stats.process(&format!("app-{i}.exe"));
        }
        assert_eq!(stats.process_snapshots().len(), 512);
    }
}
