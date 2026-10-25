//! Bounded connection lifecycle data. Packet paths only touch atomics; the UI
//! receives snapshots. Completed entries exist only while history is enabled.
use crate::config::Protocol;
use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

pub const MAX_ACTIVE: usize = 4096;
pub const MAX_COMPLETED: usize = 256;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Connecting,
    Active,
    Closing,
    Closed,
    Failed,
    Blocked,
    Stopped,
}
impl Status {
    pub fn finished(self) -> bool {
        matches!(
            self,
            Self::Closed | Self::Failed | Self::Blocked | Self::Stopped
        )
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Connecting => "Подключение",
            Self::Active => "Активно",
            Self::Closing => "Завершается",
            Self::Closed => "Завершено",
            Self::Failed => "Ошибка",
            Self::Blocked => "Заблокировано",
            Self::Stopped => "Остановлено",
        }
    }
    fn decode(value: u8) -> Self {
        match value {
            0 => Self::Connecting,
            1 => Self::Active,
            2 => Self::Closing,
            3 => Self::Closed,
            4 => Self::Failed,
            5 => Self::Blocked,
            _ => Self::Stopped,
        }
    }
}
#[derive(Clone)]
pub struct Info {
    pub pid: u32,
    pub process: String,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub protocol: Protocol,
    pub route: String,
    pub detail: String,
    pub proxied: bool,
    /// Platform monotonic timestamp of the first packet (QPC on Windows); excludes late CLOSE events
    /// from an older socket/PID/tuple. Zero is reserved for isolated fixtures.
    pub stamp: i64,
}
#[derive(Clone)]
pub struct Snapshot {
    pub id: u64,
    pub info: Info,
    pub status: Status,
}
struct Entry {
    info: Info,
    status: AtomicU8,
    last: AtomicU64,
    started: u64,
}
#[derive(Default)]
struct State {
    active: BTreeMap<u64, Arc<Entry>>,
    completed: VecDeque<Snapshot>,
    history: bool,
    recent_closes: VecDeque<Close>,
}
struct Close {
    pid: u32,
    source: SocketAddr,
    destination: SocketAddr,
    tcp: bool,
    stamp: i64,
}
impl Close {
    fn matches(&self, info: &Info) -> bool {
        info.pid == self.pid
            && (info.protocol == Protocol::Tcp) == self.tcp
            && info.source.port() == self.source.port()
            && (self.source.ip().is_unspecified() || info.source.ip() == self.source.ip())
            && (self.destination.port() == 0 || info.destination == self.destination)
            && (info.stamp == 0 || self.stamp >= info.stamp)
    }
}
pub struct Connections {
    state: Mutex<State>,
    sequence: AtomicU64,
    omitted: AtomicU64,
    epoch: Instant,
}
impl Default for Connections {
    fn default() -> Self {
        Self {
            state: Mutex::default(),
            sequence: AtomicU64::new(1),
            omitted: AtomicU64::default(),
            epoch: Instant::now(),
        }
    }
}
#[derive(Clone)]
pub struct Connection {
    id: u64,
    owner: Weak<Connections>,
    entry: Arc<Entry>,
}
pub struct Session(Connection);
impl Drop for Session {
    fn drop(&mut self) {
        self.0.finish(Status::Closed, "");
    }
}
impl Connection {
    pub fn info(&self) -> Info {
        self.entry.info.clone()
    }
    pub fn status(&self) -> Status {
        Status::decode(self.entry.status.load(Ordering::Acquire))
    }
    pub fn session(&self) -> Session {
        Session(self.clone())
    }
    pub fn touch(&self) {
        if let Some(owner) = self.owner.upgrade() {
            self.entry.last.store(owner.tick(), Ordering::Relaxed);
        }
    }
    pub fn active(&self) {
        if self.status() != Status::Connecting {
            return;
        }
        let _ = self.entry.status.compare_exchange(
            Status::Connecting as u8,
            Status::Active as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    pub fn closing(&self) {
        let mut old = self.entry.status.load(Ordering::Acquire);
        while !Status::decode(old).finished() {
            match self.entry.status.compare_exchange_weak(
                old,
                Status::Closing as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(value) => old = value,
            }
        }
    }
    pub fn finish(&self, status: Status, reason: &str) {
        debug_assert!(status.finished());
        if let Some(owner) = self.owner.upgrade() {
            owner.finish(self.id, status, reason);
        }
    }
}
impl Connections {
    fn tick(&self) -> u64 {
        self.epoch.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
    pub fn start(self: &Arc<Self>, info: Info, status: Status) -> Option<Connection> {
        debug_assert!(!status.finished());
        let mut state = self.state.lock().unwrap();
        // A fast app may close while the first intercepted packet is still
        // being attributed. Remember recent CLOSE events before publishing it.
        let already_closed = info.stamp != 0
            && state
                .recent_closes
                .iter()
                .rev()
                .any(|event| event.matches(&info));
        if !already_closed && state.active.len() >= MAX_ACTIVE {
            self.omitted.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let id = self.sequence.fetch_add(1, Ordering::Relaxed);
        let now = self.tick();
        let status = if already_closed {
            if status == Status::Connecting {
                Status::Failed
            } else {
                Status::Closed
            }
        } else {
            status
        };
        let entry = Arc::new(Entry {
            info,
            status: AtomicU8::new(status as u8),
            last: AtomicU64::new(now),
            started: now,
        });
        if already_closed {
            if state.history {
                if state.completed.len() == MAX_COMPLETED {
                    state.completed.pop_front();
                }
                state.completed.push_back(Snapshot {
                    id,
                    info: entry.info.clone(),
                    status,
                });
            }
        } else {
            state.active.insert(id, entry.clone());
        }
        Some(Connection {
            id,
            owner: Arc::downgrade(self),
            entry,
        })
    }
    pub fn completed(&self, info: Info, status: Status) {
        debug_assert!(status.finished());
        let mut state = self.state.lock().unwrap();
        if state.history {
            let id = self.sequence.fetch_add(1, Ordering::Relaxed);
            if state.completed.len() == MAX_COMPLETED {
                state.completed.pop_front();
            }
            state.completed.push_back(Snapshot { id, info, status });
        }
    }
    fn finish(&self, id: u64, status: Status, reason: &str) {
        let mut state = self.state.lock().unwrap();
        if let Some(entry) = state.active.remove(&id) {
            entry.status.store(status as u8, Ordering::Release);
            if state.history {
                let mut info = entry.info.clone();
                if !reason.is_empty() {
                    info.detail.push_str(" · ");
                    info.detail.extend(reason.chars().take(1024));
                }
                if state.completed.len() == MAX_COMPLETED {
                    state.completed.pop_front();
                }
                state.completed.push_back(Snapshot { id, info, status });
            }
        }
    }
    pub fn set_only_active(&self, only_active: bool) {
        let mut state = self.state.lock().unwrap();
        if state.history == only_active {
            state.completed.clear();
            state.history = !only_active;
        }
    }
    pub fn snapshots(&self) -> Vec<Snapshot> {
        let state = self.state.lock().unwrap();
        let mut rows = state
            .active
            .iter()
            .map(|(&id, entry)| Snapshot {
                id,
                info: entry.info.clone(),
                status: Status::decode(entry.status.load(Ordering::Acquire)),
            })
            .chain(state.completed.iter().cloned())
            .collect::<Vec<_>>();
        rows.sort_unstable_by_key(|row| std::cmp::Reverse(row.id));
        rows
    }
    pub fn omitted(&self) -> u64 {
        self.omitted.load(Ordering::Relaxed)
    }
    pub fn finish_all(&self, reason: &str) {
        let ids = self
            .state
            .lock()
            .unwrap()
            .active
            .keys()
            .copied()
            .collect::<Vec<_>>();
        for id in ids {
            self.finish(id, Status::Stopped, reason);
        }
    }
    pub fn close_socket(
        &self,
        pid: u32,
        source: SocketAddr,
        destination: SocketAddr,
        tcp: bool,
        stamp: i64,
    ) {
        let event = Close {
            pid,
            source,
            destination,
            tcp,
            stamp,
        };
        let mut state = self.state.lock().unwrap();
        let rows = state
            .active
            .iter()
            .filter(|(_, e)| event.matches(&e.info))
            .map(|(&id, e)| (id, Status::decode(e.status.load(Ordering::Acquire))))
            .collect::<Vec<_>>();
        if state.recent_closes.len() == 1024 {
            state.recent_closes.pop_front();
        }
        state.recent_closes.push_back(event);
        drop(state);
        for (id, status) in rows {
            self.finish(
                id,
                if tcp && status == Status::Connecting {
                    Status::Failed
                } else {
                    Status::Closed
                },
                "Сокет закрыт",
            );
        }
    }
    pub fn expire(&self) {
        self.expire_at(self.tick());
    }
    fn expire_at(&self, now: u64) {
        let rows = self
            .state
            .lock()
            .unwrap()
            .active
            .iter()
            .filter_map(|(&id, e)| {
                let status = Status::decode(e.status.load(Ordering::Acquire));
                if status == Status::Connecting
                    && now.saturating_sub(e.started) >= Duration::from_secs(30).as_millis() as u64
                {
                    Some((id, Status::Failed, "Таймаут подключения"))
                } else if !e.info.proxied
                    && e.info.protocol == Protocol::Udp
                    && now.saturating_sub(e.last.load(Ordering::Relaxed)) >= 90_000
                {
                    Some((id, Status::Closed, "90 с без исходящих датаграмм"))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for (id, status, reason) in rows {
            self.finish(id, status, reason);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn close_before_attribution_is_terminal_but_new_tuple_generation_stays_live() {
        let store = Arc::new(Connections::default());
        let mut row = info(Protocol::Tcp);
        store.close_socket(row.pid, row.source, row.destination, true, 300);
        let old = store.start(row.clone(), Status::Connecting).unwrap();
        assert_eq!(old.status(), Status::Failed);
        assert!(store.snapshots().is_empty());
        row.stamp = 400;
        let new = store.start(row.clone(), Status::Active).unwrap();
        assert_eq!(new.status(), Status::Active);
        store.close_socket(row.pid, row.source, row.destination, true, 300);
        assert_eq!(new.status(), Status::Active);
    }
    #[tokio::test]
    async fn cancelled_async_session_finishes_without_a_success_callback() {
        let store = Arc::new(Connections::default());
        store.set_only_active(false);
        let record = store
            .start(info(Protocol::Udp), Status::Connecting)
            .unwrap();
        let copy = record.clone();
        let (ready, started) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _session = copy.session();
            copy.active();
            let _ = ready.send(());
            std::future::pending::<()>().await;
        });
        started.await.unwrap();
        assert_eq!(record.status(), Status::Active);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(record.status(), Status::Closed);
        assert_eq!(store.snapshots().len(), 1);
    }
    #[test]
    fn active_capacity_and_terminal_attempts_do_not_invent_live_connections() {
        let store = Arc::new(Connections::default());
        store.completed(info(Protocol::Tcp), Status::Blocked);
        assert!(store.snapshots().is_empty());
        store.set_only_active(false);
        store.completed(info(Protocol::Tcp), Status::Blocked);
        assert_eq!(store.snapshots()[0].status, Status::Blocked);
        for _ in 0..MAX_ACTIVE {
            assert!(store.start(info(Protocol::Tcp), Status::Active).is_some());
        }
        assert!(store.start(info(Protocol::Udp), Status::Active).is_none());
        assert_eq!(store.omitted(), 1);
        store.set_only_active(true);
        store.finish_all("Stop");
        assert!(store.snapshots().is_empty());
    }
    fn info(protocol: Protocol) -> Info {
        Info {
            pid: 10,
            process: "game.exe".into(),
            source: "192.0.2.1:5000".parse().unwrap(),
            destination: "203.0.113.1:443".parse().unwrap(),
            protocol,
            route: "VPN".into(),
            detail: "Rule".into(),
            proxied: true,
            stamp: 200,
        }
    }
    #[test]
    fn history_starts_now_and_rechecking_discards_completed_but_keeps_live() {
        let store = Arc::new(Connections::default());
        let old = store.start(info(Protocol::Tcp), Status::Active).unwrap();
        old.finish(Status::Closed, "");
        assert!(store.snapshots().is_empty());
        let live = store
            .start(info(Protocol::Tcp), Status::Connecting)
            .unwrap();
        store.set_only_active(false);
        live.active();
        live.closing();
        assert_eq!(store.snapshots()[0].status, Status::Closing);
        live.finish(Status::Closed, "");
        let another = store.start(info(Protocol::Udp), Status::Active).unwrap();
        assert_eq!(store.snapshots().len(), 2);
        store.set_only_active(true);
        assert_eq!(store.snapshots().len(), 1);
        store.set_only_active(false);
        another.finish(Status::Failed, "test");
        assert_eq!(store.snapshots().len(), 1);
        assert_eq!(store.snapshots()[0].status, Status::Failed);
    }
    #[test]
    fn completion_is_once_bounded_and_raii_covers_abort() {
        let store = Arc::new(Connections::default());
        store.set_only_active(false);
        for _ in 0..MAX_COMPLETED + 10 {
            let c = store
                .start(info(Protocol::Tcp), Status::Connecting)
                .unwrap();
            let guard = c.session();
            c.finish(Status::Failed, "error");
            drop(guard);
        }
        assert_eq!(store.snapshots().len(), MAX_COMPLETED);
        assert!(store.snapshots().iter().all(|r| r.status == Status::Failed));
        let c = store.start(info(Protocol::Tcp), Status::Active).unwrap();
        let guard = c.session();
        drop(guard);
        assert_eq!(store.snapshots()[0].status, Status::Closed);
    }
    #[test]
    fn socket_close_rejects_old_generation_and_udp_expiration_is_explicit() {
        let store = Arc::new(Connections::default());
        store.set_only_active(false);
        let row = info(Protocol::Tcp);
        let c = store.start(row.clone(), Status::Active).unwrap();
        store.close_socket(10, row.source, row.destination, true, 100);
        assert!(!c.status().finished());
        store.close_socket(11, row.source, row.destination, true, 300);
        assert!(!c.status().finished());
        store.close_socket(10, row.source, row.destination, true, 300);
        assert_eq!(c.status(), Status::Closed);
        let mut row = info(Protocol::Udp);
        row.proxied = false;
        let c = store.start(row, Status::Active).unwrap();
        store.expire_at(120_000);
        assert_eq!(c.status(), Status::Closed);
    }
}
