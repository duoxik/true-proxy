//! Bounded connection lifecycle data. Packet paths only touch atomics; the UI
//! receives snapshots. Completed entries exist only while history is enabled.
use crate::config::{Action, Protocol};
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
    const FINISHED: [Self; 4] = [Self::Closed, Self::Failed, Self::Blocked, Self::Stopped];

    pub fn finished(self) -> bool {
        matches!(
            self,
            Self::Closed | Self::Failed | Self::Blocked | Self::Stopped
        )
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Connecting => "Connecting",
            Self::Active => "Active",
            Self::Closing => "Closing",
            Self::Closed => "Closed",
            Self::Failed => "Failed",
            Self::Blocked => "Blocked",
            Self::Stopped => "Stopped",
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
    /// Stable route identity, independent of a proxy's mutable display name.
    pub action: Action,
    /// Platform monotonic timestamp of the first packet (QPC on Windows); excludes late CLOSE events
    /// from an older socket/PID/tuple. Zero is reserved for isolated fixtures.
    pub stamp: i64,
}
#[derive(Clone)]
pub struct Snapshot {
    pub id: u64,
    pub info: Info,
    pub status: Status,
    pub timing: Option<Timing>,
}
#[derive(Clone, Copy)]
pub struct Timing {
    /// Local hour, minute, and second at observation.
    pub local_start: Option<(u16, u16, u16)>,
    pub elapsed: Duration,
}
struct Entry {
    info: Info,
    status: AtomicU8,
    last: AtomicU64,
    started: u64,
    local_start: Option<(u16, u16, u16)>,
    passive: bool,
}
impl Entry {
    fn timing(&self, now: u64) -> Timing {
        Timing {
            local_start: self.local_start,
            elapsed: Duration::from_millis(now.saturating_sub(self.started)),
        }
    }
}
#[derive(Default)]
struct State {
    active: BTreeMap<u64, Arc<Entry>>,
    completed: VecDeque<Snapshot>,
    history_since: [Option<u64>; Status::FINISHED.len()],
    recent_closes: VecDeque<Close>,
}
struct Close {
    pid: u32,
    source: SocketAddr,
    destination: SocketAddr,
    tcp: bool,
    stamp: i64,
    history: HistoryEvent,
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
    /// Even revisions are off; odd revisions identify one observation session.
    observation: AtomicU64,
    history_selection: AtomicU64,
    sequence: AtomicU64,
    omitted: AtomicU64,
    epoch: Instant,
}
/// Observation and filter boundary captured when a terminal event occurs.
#[derive(Clone, Copy)]
pub struct HistoryEvent {
    observation: u64,
    selection: u64,
}
impl Default for Connections {
    fn default() -> Self {
        Self {
            state: Mutex::default(),
            observation: AtomicU64::new(0),
            history_selection: AtomicU64::new(0),
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
            owner.finish_observed(self.id, status, reason, Some(owner.history_event()));
        }
    }
    pub fn finish_since(&self, status: Status, reason: &str, event: HistoryEvent) {
        debug_assert!(status.finished());
        if let Some(owner) = self.owner.upgrade() {
            owner.finish_observed(self.id, status, reason, Some(event));
        }
    }
    pub fn discard(&self) {
        if let Some(owner) = self.owner.upgrade() {
            owner.finish_observed(self.id, Status::Stopped, "", None);
        }
    }
}
impl Connections {
    pub fn tracking(&self) -> bool {
        self.observation.load(Ordering::Acquire) & 1 != 0
    }
    pub fn set_tracking(&self, enabled: bool) {
        let mut state = self.state.lock().unwrap();
        let revision = self.observation.load(Ordering::Relaxed);
        if (revision & 1 != 0) == enabled {
            return;
        }
        self.observation
            .store(revision.wrapping_add(1), Ordering::Release);
        if !enabled {
            state.completed.clear();
            state.active.retain(|_, entry| {
                if entry.passive {
                    entry.status.store(Status::Stopped as u8, Ordering::Release);
                }
                !entry.passive
            });
            self.omitted.store(0, Ordering::Relaxed);
        }
    }
    pub fn history_event(&self) -> HistoryEvent {
        HistoryEvent {
            observation: self.observation.load(Ordering::Acquire),
            selection: self.history_selection.load(Ordering::Acquire),
        }
    }
    pub fn is_observing(&self, event: HistoryEvent) -> bool {
        event.observation & 1 != 0 && self.observation.load(Ordering::Acquire) == event.observation
    }
    fn accepts_history(&self, state: &State, status: Status, event: HistoryEvent) -> bool {
        self.is_observing(event)
            && state.history_since[status as usize - Status::Closed as usize]
                .is_some_and(|since| event.selection >= since)
    }
    fn revision(&self) -> Option<u64> {
        let revision = self.observation.load(Ordering::Acquire);
        (revision & 1 != 0).then_some(revision)
    }
    fn same_revision(&self, revision: u64) -> bool {
        self.observation.load(Ordering::Relaxed) == revision
    }
    fn tick(&self) -> u64 {
        self.epoch.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
    pub fn start(self: &Arc<Self>, info: Info, status: Status) -> Option<Connection> {
        self.start_entry(info, status, None)
    }
    pub fn start_passive(
        self: &Arc<Self>,
        info: Info,
        status: Status,
        event: HistoryEvent,
    ) -> Option<Connection> {
        self.start_entry(info, status, Some(event))
    }
    fn start_entry(
        self: &Arc<Self>,
        info: Info,
        status: Status,
        passive: Option<HistoryEvent>,
    ) -> Option<Connection> {
        debug_assert!(!status.finished());
        let mut state = self.state.lock().unwrap();
        if passive.is_some_and(|event| !self.is_observing(event)) {
            return None;
        }
        // A fast app may close while the first intercepted packet is still
        // being attributed. Remember recent CLOSE events before publishing it.
        let close = if passive.is_some() || info.stamp == 0 {
            None
        } else {
            state
                .recent_closes
                .iter()
                .rev()
                .find(|event| event.matches(&info))
        };
        let already_closed = close.is_some();
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
            local_start: crate::platform::local_clock(),
            passive: passive.is_some(),
        });
        if let Some(close) = close {
            if self.accepts_history(&state, status, close.history) {
                if state.completed.len() == MAX_COMPLETED {
                    state.completed.pop_front();
                }
                state.completed.push_back(Snapshot {
                    id,
                    info: entry.info.clone(),
                    status,
                    timing: None,
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
        let event = self.history_event();
        if !self.is_observing(event) {
            return;
        }
        let mut state = self.state.lock().unwrap();
        if self.accepts_history(&state, status, event) {
            let id = self.sequence.fetch_add(1, Ordering::Relaxed);
            if state.completed.len() == MAX_COMPLETED {
                state.completed.pop_front();
            }
            state.completed.push_back(Snapshot {
                id,
                info,
                status,
                timing: None,
            });
        }
    }
    fn finish_observed(&self, id: u64, status: Status, reason: &str, event: Option<HistoryEvent>) {
        let mut state = self.state.lock().unwrap();
        if let Some(entry) = state.active.remove(&id) {
            entry.status.store(status as u8, Ordering::Release);
            if event.is_some_and(|event| self.accepts_history(&state, status, event)) {
                let mut info = entry.info.clone();
                if !reason.is_empty() {
                    info.detail.push_str(" · ");
                    info.detail.extend(reason.chars().take(1024));
                }
                if state.completed.len() == MAX_COMPLETED {
                    state.completed.pop_front();
                }
                state.completed.push_back(Snapshot {
                    id,
                    info,
                    status,
                    timing: Some(entry.timing(self.tick())),
                });
            }
        }
    }
    #[cfg(test)]
    pub fn set_only_active(&self, only_active: bool) {
        self.set_history_statuses(if only_active { &[] } else { &Status::FINISHED });
    }
    pub fn set_history_statuses(&self, statuses: &[Status]) {
        let mut state = self.state.lock().unwrap();
        let selected = Status::FINISHED.map(|status| statuses.contains(&status));
        if state.history_since.map(|since| since.is_some()) == selected {
            return;
        }
        let selection = self.history_selection.fetch_add(1, Ordering::AcqRel) + 1;
        for (since, selected) in state.history_since.iter_mut().zip(selected) {
            *since = selected.then(|| since.unwrap_or(selection));
        }
        state.completed.retain(|row| statuses.contains(&row.status));
    }
    pub fn snapshots(&self) -> Vec<Snapshot> {
        let Some(revision) = self.revision() else {
            return Vec::new();
        };
        let state = self.state.lock().unwrap();
        if !self.same_revision(revision) {
            return Vec::new();
        }
        let now = self.tick();
        let mut rows = state
            .active
            .iter()
            .map(|(&id, entry)| Snapshot {
                id,
                info: entry.info.clone(),
                status: Status::decode(entry.status.load(Ordering::Acquire)),
                timing: Some(entry.timing(now)),
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
        let event = self.history_event();
        let ids = self
            .state
            .lock()
            .unwrap()
            .active
            .iter()
            .filter_map(|(&id, entry)| (!entry.passive).then_some(id))
            .collect::<Vec<_>>();
        for id in ids {
            self.finish_observed(id, Status::Stopped, reason, Some(event));
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
        let history = self.history_event();
        let event = Close {
            pid,
            source,
            destination,
            tcp,
            stamp,
            history,
        };
        let mut state = self.state.lock().unwrap();
        let rows = state
            .active
            .iter()
            .filter(|(_, e)| !e.passive && event.matches(&e.info))
            .map(|(&id, e)| (id, Status::decode(e.status.load(Ordering::Acquire))))
            .collect::<Vec<_>>();
        if state.recent_closes.len() == 1024 {
            state.recent_closes.pop_front();
        }
        state.recent_closes.push_back(event);
        drop(state);
        for (id, status) in rows {
            self.finish_observed(
                id,
                if tcp && status == Status::Connecting {
                    Status::Failed
                } else {
                    Status::Closed
                },
                "Socket closed",
                Some(history),
            );
        }
    }
    pub fn expire(&self) {
        self.expire_at(self.tick());
    }
    fn expire_at(&self, now: u64) {
        let event = self.history_event();
        let rows = {
            let state = self.state.lock().unwrap();
            state
                .active
                .iter()
                .filter(|(_, entry)| !entry.passive)
                .filter_map(|(&id, e)| {
                    let status = Status::decode(e.status.load(Ordering::Acquire));
                    if status == Status::Connecting
                        && now.saturating_sub(e.started)
                            >= Duration::from_secs(30).as_millis() as u64
                    {
                        Some((id, Status::Failed, "Connection timed out"))
                    } else if e.info.action == Action::Direct
                        && e.info.protocol == Protocol::Udp
                        && now.saturating_sub(e.last.load(Ordering::Relaxed)) >= 90_000
                    {
                        Some((id, Status::Closed, "No outgoing datagrams for 90 s"))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        };
        for (id, status, reason) in rows {
            self.finish_observed(id, status, reason, Some(event));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hidden_history_and_snapshots_do_not_wait_for_the_registry() {
        let store = Arc::new(Connections::default());
        assert!(!store.tracking());
        let locked = store.state.lock().unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        let copy = store.clone();
        let worker = std::thread::spawn(move || {
            copy.completed(info(Protocol::Udp), Status::Blocked);
            assert!(copy.snapshots().is_empty());
            sent.send(()).unwrap();
        });
        let result = received.recv_timeout(Duration::from_secs(3));
        drop(locked);
        worker.join().unwrap();
        assert!(
            result.is_ok(),
            "Disabled recording must not wait for its registry mutex"
        );
        assert_eq!(store.omitted(), 0);
    }

    #[test]
    fn opening_the_view_restores_live_rows_and_discards_previous_history() {
        let store = Arc::new(Connections::default());
        store.set_tracking(true);
        store.set_only_active(false);
        let old = store.start(info(Protocol::Tcp), Status::Active).unwrap();
        let old_session = old.session();
        let completed = store.start(info(Protocol::Udp), Status::Active).unwrap();
        let observed = store.snapshots()[0].timing.unwrap();
        completed.finish(Status::Closed, "");
        let closed = store.snapshots()[0].timing.unwrap();
        assert_eq!(closed.local_start, observed.local_start);
        assert!(closed.elapsed >= observed.elapsed);
        let row = old.info();
        store.close_socket(row.pid + 1, row.source, row.destination, true, 999);
        let snapshots = store.snapshots();
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].timing.unwrap().elapsed, closed.elapsed);
        store.set_tracking(false);
        assert_eq!(old.status(), Status::Active);
        assert!(store.snapshots().is_empty());
        let hidden = store.start(info(Protocol::Udp), Status::Active).unwrap();
        let fresh = store
            .start(info(Protocol::Tcp), Status::Connecting)
            .unwrap();
        hidden.finish(Status::Closed, "Closed while hidden");
        store.completed(info(Protocol::Udp), Status::Blocked);
        store.set_tracking(true);
        let rows = store.snapshots();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, fresh.id);
        assert_eq!(rows[0].status, Status::Connecting);
        assert_eq!(rows[1].id, old.id);
        assert_eq!(rows[1].status, Status::Active);
        drop(old_session);
        assert_eq!(store.snapshots()[1].status, Status::Closed);
        store.set_tracking(false);
        store.finish_all("Routing stopped");
        store.set_tracking(true);
        assert!(store.snapshots().is_empty());
    }

    #[test]
    fn close_before_attribution_is_terminal_but_new_tuple_generation_stays_live() {
        let store = Arc::new(Connections::default());
        let mut row = info(Protocol::Tcp);
        store.close_socket(row.pid, row.source, row.destination, true, 300);
        store.set_tracking(true);
        store.set_only_active(false);
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
        store.set_tracking(true);
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
        store.set_tracking(true);
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
        store.set_tracking(false);
        assert_eq!(store.omitted(), 0);
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
            action: Action::Proxy("vpn".into()),
            stamp: 200,
        }
    }
    #[test]
    fn history_starts_now_and_rechecking_discards_completed_but_keeps_live() {
        let store = Arc::new(Connections::default());
        store.set_tracking(true);
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
    fn each_terminal_status_has_its_own_selection_boundary() {
        let store = Arc::new(Connections::default());
        store.set_tracking(true);
        store.set_history_statuses(&[Status::Failed]);
        let before_closed_selected = store.history_event();
        let failed = store
            .start(info(Protocol::Tcp), Status::Connecting)
            .unwrap();
        let closed = store.start(info(Protocol::Tcp), Status::Active).unwrap();

        store.set_history_statuses(&[Status::Failed, Status::Closed]);
        failed.finish_since(Status::Failed, "", before_closed_selected);
        closed.finish_since(Status::Closed, "", before_closed_selected);
        assert_eq!(store.snapshots().len(), 1);
        assert_eq!(store.snapshots()[0].status, Status::Failed);

        let closed = store.start(info(Protocol::Tcp), Status::Active).unwrap();
        let before_reselection = store.history_event();
        closed.finish(Status::Closed, "");
        assert_eq!(store.snapshots().len(), 2);
        store.set_history_statuses(&[Status::Failed]);
        store.set_history_statuses(&[Status::Closed, Status::Failed]);
        let closed = store.start(info(Protocol::Tcp), Status::Active).unwrap();
        closed.finish_since(Status::Closed, "", before_reselection);
        assert_eq!(store.snapshots().len(), 1);
    }

    #[test]
    fn passive_rows_are_scoped_to_the_visible_observation() {
        let store = Arc::new(Connections::default());
        store.set_tracking(true);
        let old = store.history_event();
        let record = store
            .start_passive(info(Protocol::Tcp), Status::Active, old)
            .unwrap();
        store.finish_all("Routing stopped");
        assert_eq!(record.status(), Status::Active);
        store.set_tracking(false);
        store.set_tracking(true);
        assert!(store.snapshots().is_empty());
        assert!(!store.is_observing(old));
        assert!(
            store
                .start_passive(info(Protocol::Tcp), Status::Active, old)
                .is_none()
        );
    }
    #[test]
    fn completion_is_once_bounded_and_raii_covers_abort() {
        let store = Arc::new(Connections::default());
        store.set_tracking(true);
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
        store.set_tracking(true);
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
        row.action = Action::Direct;
        let c = store.start(row, Status::Active).unwrap();
        store.expire_at(120_000);
        assert_eq!(c.status(), Status::Closed);
    }
}
