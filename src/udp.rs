//! Bounded SOCKS UDP associations, shared by the peers of one original socket.
//! Platform injection is a callback so transport/lifecycle tests never open a driver.
use crate::{
    config::{Action, Config, Protocol},
    connections::{Connection, Info, Session, Status},
    dns::DomainCache,
    engine::{ConnectionGuard, Statistics},
    packet::{FlowKey, udp_reply},
    rules::{self, Flow},
    socks,
};
use anyhow::{Result, bail};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncReadExt,
    runtime::Handle,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
};

const MAX_ASSOCIATIONS: usize = 512;
const MAX_PEERS: usize = 4096;
const MAX_PEERS_PER_ASSOCIATION: usize = 256;
const IDLE: Duration = Duration::from_secs(90);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SocketId {
    pub pid: u32,
    pub local: SocketAddr,
    pub generation: (u64, u64, u64),
}
#[derive(Clone, Copy)]
pub(crate) struct Owner<'a> {
    pub name: &'a str,
    pub path: &'a str,
}
pub(crate) struct Outgoing<'a, A> {
    pub destination: SocketAddr,
    pub payload: &'a [u8],
    pub address: A,
    pub stamp: i64,
}
pub(crate) struct Context<A> {
    pub config: Arc<Config>,
    pub domains: Arc<Mutex<DomainCache>>,
    pub stats: Arc<Statistics>,
    pub inject: Arc<dyn Fn(Vec<u8>, A) -> Result<()> + Send + Sync>,
    pub valid: Arc<dyn Fn(SocketId, i64) -> bool + Send + Sync>,
}
struct Shared<A> {
    context: Context<A>,
    memory: Arc<Semaphore>,
    peers: Arc<Semaphore>,
    domain_rules: bool,
}
impl<A> Shared<A> {
    fn allows(&self, key: &Key, owner: Owner<'_>, remote: SocketAddr) -> bool {
        if remote.port() == 0
            || remote.ip().is_unspecified()
            || key.local.is_ipv4() != remote.is_ipv4()
        {
            return false;
        }
        let names = if self.domain_rules {
            self.context.domains.lock().unwrap().lookup(remote.ip())
        } else {
            Vec::new()
        };
        matches!(rules::resolve(&self.context.config,&Flow {process_name:owner.name,process_path:owner.path,destination:remote,protocol:Protocol::Udp,domains:&names}),Action::Proxy(id) if id==key.proxy)
    }
    fn blocked(&self) {
        self.context.stats.blocked.fetch_add(1, Ordering::Relaxed);
    }
}
#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    // The index is stable across peers. Entry.birth and Context.valid distinguish
    // socket incarnations without replacing a truly new relay on a late old CLOSE.
    pid: u32,
    local: SocketAddr,
    proxy: String,
}
struct Frame<A> {
    destination: SocketAddr,
    payload: Vec<u8>,
    address: A,
    stamp: i64,
    _memory: OwnedSemaphorePermit,
}
enum Command<A> {
    Data(Frame<A>),
    Forget(SocketAddr),
}
struct Entry<A> {
    socket: SocketId,
    birth: i64,
    sender: mpsc::Sender<Command<A>>,
    task: tokio::task::JoinHandle<()>,
    alive: Arc<AtomicBool>,
}
impl<A> Drop for Entry<A> {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
        self.task.abort();
    }
}
pub(crate) struct Pool<A> {
    entries: HashMap<Key, Entry<A>>,
    shared: Arc<Shared<A>>,
    runtime: Handle,
}
impl<A: Copy + Send + Sync + 'static> Pool<A> {
    pub fn new(context: Context<A>, runtime: Handle) -> Self {
        let domain_rules = context
            .config
            .rules
            .iter()
            .any(|r| r.enabled && (!r.domains.is_empty() || !r.domain_suffixes.is_empty()));
        Self {
            entries: HashMap::new(),
            shared: Arc::new(Shared {
                context,
                memory: Arc::new(Semaphore::new(4 * 1024 * 1024)),
                peers: Arc::new(Semaphore::new(MAX_PEERS)),
                domain_rules,
            }),
            runtime,
        }
    }
    pub fn cleanup(&mut self) {
        self.entries
            .retain(|_, e| !e.sender.is_closed() && (self.shared.context.valid)(e.socket, e.birth));
    }
    pub fn send(
        &mut self,
        socket: SocketId,
        owner: Owner<'_>,
        proxy: &str,
        outgoing: Outgoing<'_, A>,
    ) -> Result<()> {
        let key = Key {
            pid: socket.pid,
            local: socket.local,
            proxy: proxy.into(),
        };
        if !(self.shared.context.valid)(socket, outgoing.stamp)
            || !self.shared.allows(&key, owner, outgoing.destination)
        {
            self.shared.blocked();
            bail!("UDP-адрес не разрешён для этой SOCKS-ассоциации");
        }
        let memory = self
            .shared
            .memory
            .clone()
            .try_acquire_many_owned(outgoing.payload.len() as u32)
            .map_err(|_| {
                self.shared.blocked();
                anyhow::anyhow!("Лимит памяти очередей UDP")
            })?;
        if self.entries.get(&key).is_some_and(|entry| {
            entry.sender.is_closed() || !(self.shared.context.valid)(entry.socket, entry.birth)
        }) {
            self.entries.remove(&key);
        }
        if !self.entries.contains_key(&key) {
            self.cleanup();
            // A newly identified PID must not inherit the previous owner's relay.
            // Same-PID port reuse becomes observable when its CLOSE is delivered.
            self.entries
                .retain(|old, _| old.local != socket.local || old.pid == socket.pid);
            if self.entries.len() >= MAX_ASSOCIATIONS {
                self.shared.blocked();
                bail!("Лимит UDP-ассоциаций");
            }
            let (tx, rx) = mpsc::channel(16);
            let alive = Arc::new(AtomicBool::new(true));
            let task = self.runtime.spawn(session(
                Key {
                    pid: socket.pid,
                    local: socket.local,
                    proxy: proxy.into(),
                },
                socket,
                owner.name.into(),
                owner.path.into(),
                rx,
                self.shared.clone(),
                alive.clone(),
            ));
            self.entries.insert(
                key.clone(),
                Entry {
                    socket,
                    birth: outgoing.stamp,
                    sender: tx,
                    task,
                    alive,
                },
            );
        }
        self.entries[&key]
            .sender
            .try_send(Command::Data(Frame {
                destination: outgoing.destination,
                payload: outgoing.payload.to_vec(),
                address: outgoing.address,
                stamp: outgoing.stamp,
                _memory: memory,
            }))
            .map_err(|_| {
                self.shared.blocked();
                anyhow::anyhow!("Очередь UDP заполнена или закрыта")
            })
    }
    /// A destination changing route must not tear down other compatible peers.
    pub fn forget(&mut self, socket: SocketId, remote: SocketAddr) {
        self.entries.retain(|key, e| {
            key.pid != socket.pid
                || key.local != socket.local
                || e.sender.try_send(Command::Forget(remote)).is_ok()
        });
    }
}
struct Peer {
    record: Option<Connection>,
    _session: Option<Session>,
    counter: Option<ConnectionGuard>,
    last: Instant,
    _slot: OwnedSemaphorePermit,
}
struct State<A> {
    key: Key,
    socket: SocketId,
    name: String,
    path: String,
    shared: Arc<Shared<A>>,
    peers: HashMap<SocketAddr, Peer>,
    address: A,
    /// Immutable QPC of the first Data creating this association, never the latest Data.
    stamp: i64,
    last: Instant,
    alive: Arc<AtomicBool>,
}
impl<A: Copy> State<A> {
    fn valid(&self) -> bool {
        self.alive.load(Ordering::Acquire) && (self.shared.context.valid)(self.socket, self.stamp)
    }
    fn expire(&mut self, now: Instant) -> bool {
        self.peers.retain(|_, p| now.duration_since(p.last) < IDLE);
        now.duration_since(self.last) >= IDLE
    }
    fn allows(&self, remote: SocketAddr) -> bool {
        self.shared.allows(
            &self.key,
            Owner {
                name: &self.name,
                path: &self.path,
            },
            remote,
        )
    }
    fn peer(&mut self, remote: SocketAddr, stamp: i64, status: Status) -> bool {
        if let Some(peer) = self.peers.get_mut(&remote)
            && peer
                .record
                .as_ref()
                .is_some_and(|record| record.status().finished())
        {
            // Journal sessions may end while the socket and peer stay alive.
            // Never release transport slots/counters or recreate an old peer
            // merely because the view was closed or its record expired.
            peer.record = None;
            peer._session = None;
        }
        if !self.peers.contains_key(&remote) {
            if self.peers.len() >= MAX_PEERS_PER_ASSOCIATION {
                self.shared.blocked();
                return false;
            }
            let Ok(slot) = self.shared.peers.clone().try_acquire_owned() else {
                self.shared.blocked();
                return false;
            };
            let ctx = &self.shared.context;
            let record = if ctx.stats.activity.tracking() {
                let names = ctx.domains.lock().unwrap().lookup(remote.ip());
                let info = Info {
                    pid: self.key.pid,
                    process: self.name.clone(),
                    source: self.key.local,
                    destination: remote,
                    protocol: Protocol::Udp,
                    route: ctx
                        .config
                        .proxy(&self.key.proxy)
                        .map(|p| p.name.clone())
                        .unwrap_or_default(),
                    detail: rules::explanation(
                        &ctx.config,
                        &Flow {
                            process_name: &self.name,
                            process_path: &self.path,
                            destination: remote,
                            protocol: Protocol::Udp,
                            domains: &names,
                        },
                    ),
                    action: Action::Proxy(self.key.proxy.clone()),
                    stamp,
                };
                ctx.stats.activity.start(info, status)
            } else {
                None
            };
            let lifetime = record.as_ref().map(Connection::session);
            self.peers.insert(
                remote,
                Peer {
                    record,
                    _session: lifetime,
                    counter: None,
                    last: Instant::now(),
                    _slot: slot,
                },
            );
        }
        let peer = self.peers.get_mut(&remote).unwrap();
        peer.last = Instant::now();
        if status == Status::Active {
            if let Some(c) = &peer.record {
                c.active();
                c.touch();
            }
            if peer.counter.is_none() {
                peer.counter = Some(self.shared.context.stats.connection(&self.name));
            }
        }
        true
    }
    async fn send(&mut self, frame: Frame<A>, socket: &tokio::net::UdpSocket) -> Result<()> {
        if !self.valid() {
            return Ok(());
        }
        if !self.allows(frame.destination) {
            self.peers.remove(&frame.destination);
            self.shared.blocked();
            return Ok(());
        }
        if !self.peer(frame.destination, frame.stamp, Status::Connecting) {
            return Ok(());
        }
        let mut packet = vec![0, 0, 0];
        socks::encode_address(frame.destination, &mut packet);
        packet.extend_from_slice(&frame.payload);
        socket.send(&packet).await?;
        self.address = frame.address;
        self.last = Instant::now();
        self.peer(frame.destination, frame.stamp, Status::Active);
        self.shared
            .context
            .stats
            .uploaded
            .fetch_add(frame.payload.len() as u64, Ordering::Relaxed);
        if let Some(counter) = self
            .peers
            .get(&frame.destination)
            .and_then(|p| p.counter.as_ref())
        {
            counter
                .process
                .uploaded
                .fetch_add(frame.payload.len() as u64, Ordering::Relaxed);
        }
        Ok(())
    }
    fn receive(&mut self, bytes: &[u8]) -> Result<()> {
        if !self.valid() {
            return Ok(());
        }
        let Ok((source, payload)) = socks::udp_payload(bytes) else {
            self.shared.blocked();
            return Ok(());
        };
        if !self.allows(source) {
            self.peers.remove(&source);
            self.shared.blocked();
            return Ok(());
        }
        if !self.peer(source, self.stamp, Status::Active) {
            return Ok(());
        }
        // The embedded source is the real peer, not the relay or the first destination.
        let packet = udp_reply(
            FlowKey {
                source: self.key.local,
                destination: source,
            },
            payload,
        )?;
        if !self.valid() {
            return Ok(());
        }
        (self.shared.context.inject)(packet, self.address)?;
        self.last = Instant::now();
        self.shared
            .context
            .stats
            .downloaded
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        if let Some(counter) = self.peers.get(&source).and_then(|p| p.counter.as_ref()) {
            counter
                .process
                .downloaded
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
        }
        Ok(())
    }
}
async fn session<A: Copy + Send + Sync + 'static>(
    key: Key,
    socket: SocketId,
    name: String,
    path: String,
    mut rx: mpsc::Receiver<Command<A>>,
    shared: Arc<Shared<A>>,
    alive: Arc<AtomicBool>,
) {
    let Some(Command::Data(first)) = rx.recv().await else {
        return;
    };
    let mut state = State {
        key,
        socket,
        name,
        path,
        shared,
        peers: HashMap::new(),
        address: first.address,
        stamp: first.stamp,
        last: Instant::now(),
        alive,
    };
    if !state.valid() {
        return;
    }
    if !state.peer(first.destination, first.stamp, Status::Connecting) {
        return;
    }
    let result = async {
        let association =
            socks::associate(state.shared.context.config.proxy(&state.key.proxy)?).await?;
        let mut control = association.control;
        let mut control_byte = [0];
        let mut bytes = vec![0; 65535];
        state.send(first, &association.socket).await?;
        let mut timer = tokio::time::interval(Duration::from_secs(1));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                command = rx.recv() => {
                    if !state.valid() { break; }
                    match command {
                        Some(Command::Data(frame)) => state.send(frame, &association.socket).await?,
                        Some(Command::Forget(remote)) => { state.peers.remove(&remote); }
                        None => break,
                    }
                }
                reply = association.socket.recv(&mut bytes) => {
                    let length = reply?;
                    if !state.valid() { break; }
                    state.receive(&bytes[..length])?;
                }
                _ = timer.tick() => {
                    if !state.valid() || state.expire(Instant::now()) { break; }
                }
                _ = control.read(&mut control_byte) => bail!("SOCKS5-сервер закрыл UDP ASSOCIATE"),
            }
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(error) = result {
        for peer in state.peers.values() {
            if let Some(record) = &peer.record {
                record.finish(Status::Failed, &format!("{error:#}"));
            }
        }
        state.shared.context.stats.log(
            &state.name,
            state.key.local.to_string(),
            "Ошибка",
            format!("{error:#}"),
        );
        state.shared.blocked();
    }
}

#[cfg(test)]
mod tests;
