//! The production association pool, a real loopback SOCKS server and an in-memory
//! packet sink. No driver, elevation, application traffic or user profile access.
use super::*;
use crate::{config::Proxy, packet::Packet};
use std::sync::atomic::{AtomicU64, AtomicUsize};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, UdpSocket},
    time::timeout,
};

struct Frame {
    association: usize,
    target: SocketAddr,
    payload: Vec<u8>,
    client: SocketAddr,
    relay: Arc<UdpSocket>,
    stop: mpsc::UnboundedSender<()>,
}
impl Frame {
    async fn reply(&self, source: &str, data: &[u8]) {
        let mut packet = vec![0, 0, 0];
        socks::encode_address(source.parse().unwrap(), &mut packet);
        packet.extend_from_slice(data);
        self.relay.send_to(&packet, self.client).await.unwrap();
    }
}
struct Mock {
    proxy: Proxy,
    frames: mpsc::UnboundedReceiver<Frame>,
    opened: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Mock {
    async fn new(id: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, frames) = mpsc::unbounded_channel();
        let opened = Arc::new(AtomicUsize::new(0));
        let count = opened.clone();
        let task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    connection = listener.accept() => {
                        let (mut control, _) = connection.unwrap();
                        let tx = tx.clone();
                        let association = count.fetch_add(1, Ordering::Relaxed) + 1;
                        tasks.spawn(async move {
                            let mut greeting = [0; 3];
                            control.read_exact(&mut greeting).await.unwrap();
                            assert_eq!(greeting, [5, 1, 0]);
                            control.write_all(&[5, 0]).await.unwrap();
                            let mut request = [0; 10];
                            control.read_exact(&mut request).await.unwrap();
                            assert_eq!(&request[..4], &[5, 3, 0, 1]);
                            let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                            let mut response = vec![5, 0, 0];
                            socks::encode_address(relay.local_addr().unwrap(), &mut response);
                            control.write_all(&response).await.unwrap();
                            let mut bytes = [0; 65535];
                            let mut end = [0];
                            let (stop,mut stopped)=mpsc::unbounded_channel();
                            loop {
                                tokio::select! {
                                    data = relay.recv_from(&mut bytes) => {
                                        let (len, client) = data.unwrap();
                                        let (target, payload) = socks::udp_payload(&bytes[..len]).unwrap();
                                        if tx.send(Frame {association, target, payload:payload.to_vec(),client,relay:relay.clone(),stop:stop.clone()}).is_err() {break;}
                                    }
                                    _ = control.read(&mut end) => break,
                                    _ = stopped.recv() => break,
                                }
                            }
                        });
                    }
                    _ = tasks.join_next(), if !tasks.is_empty() => {},
                }
            }
        });
        Self {
            proxy: Proxy {
                id: id.into(),
                name: id.into(),
                host: "127.0.0.1".into(),
                port,
                username: String::new(),
                protected_password: None,
            },
            frames,
            opened,
            task,
        }
    }
    async fn frame(&mut self) -> Frame {
        timeout(Duration::from_secs(3), self.frames.recv())
            .await
            .unwrap()
            .unwrap()
    }
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct Fixture {
    pool: Pool<u64>,
    socket: SocketId,
    packets: mpsc::UnboundedReceiver<(Vec<u8>, u64)>,
    generation: Arc<AtomicU64>,
    stats: Arc<Statistics>,
    domains: Arc<Mutex<DomainCache>>,
    stamp: i64,
}
impl Fixture {
    fn observe_name(&self, ip: &str, name: &str, ttl: u32) {
        let mut answer = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        for label in name.split('.') {
            answer.push(label.len() as u8);
            answer.extend_from_slice(label.as_bytes());
        }
        answer.extend_from_slice(&[0, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1]);
        answer.extend_from_slice(&ttl.to_be_bytes());
        answer.extend_from_slice(&[0, 4]);
        answer.extend_from_slice(&ip.parse::<std::net::Ipv4Addr>().unwrap().octets());
        self.domains.lock().unwrap().observe(&answer);
    }
    fn new(config: Config) -> Self {
        config.validate().unwrap();
        let (tx, packets) = mpsc::unbounded_channel();
        let generation = Arc::new(AtomicU64::new(0));
        let current = generation.clone();
        let stats = Arc::new(Statistics::default());
        stats.activity.set_only_active(false);
        let domains = Arc::new(Mutex::new(DomainCache::default()));
        let context = Context {
            config: Arc::new(config),
            domains: domains.clone(),
            stats: stats.clone(),
            inject: Arc::new(move |bytes, address| {
                tx.send((bytes, address))?;
                Ok(())
            }),
            valid: Arc::new(move |id, _birth| id.generation.0 == current.load(Ordering::Acquire)),
        };
        Self {
            pool: Pool::new(context, tokio::runtime::Handle::current()),
            socket: SocketId {
                pid: 123,
                local: "192.0.2.10:3097".parse().unwrap(),
                generation: (0, 0, 0),
            },
            packets,
            generation,
            stats,
            domains,
            stamp: 0,
        }
    }
    fn send(&mut self, proxy: &str, target: &str, data: &[u8]) -> Result<()> {
        self.pool.send(
            self.socket,
            Owner {
                name: "game.exe",
                path: "C:\\Games\\game.exe",
            },
            proxy,
            Outgoing {
                destination: target.parse().unwrap(),
                payload: data,
                address: 42,
                stamp: self.stamp,
            },
        )
    }
    async fn packet(&mut self, source: &str, data: &[u8]) {
        let (bytes, address) = timeout(Duration::from_secs(3), self.packets.recv())
            .await
            .unwrap()
            .unwrap();
        let p = Packet::parse(&bytes).unwrap();
        assert_eq!(p.flow.source, source.parse::<SocketAddr>().unwrap());
        assert_eq!(p.flow.destination, self.socket.local);
        assert_eq!(p.payload(&bytes), data);
        assert_eq!(address, 42);
    }
}
fn config(proxies: Vec<Proxy>) -> Config {
    Config {
        default_action: Action::Proxy(proxies[0].id.clone()),
        proxies,
        ..Config::default()
    }
}

#[tokio::test]
async fn a_and_b_share_one_association_and_source_socket() {
    let mut mock = Mock::new("p").await;
    let mut f = Fixture::new(config(vec![mock.proxy.clone()]));
    f.send("p", "203.0.113.7:3478", b"A").unwrap();
    f.send("p", "198.51.100.9:3097", b"B").unwrap();
    let a = mock.frame().await;
    let b = mock.frame().await;
    assert_eq!(a.target, "203.0.113.7:3478".parse().unwrap());
    assert_eq!(b.target, "198.51.100.9:3097".parse().unwrap());
    assert_eq!((&a.payload[..], &b.payload[..]), (&b"A"[..], &b"B"[..]));
    assert_eq!(a.association, b.association);
    assert_eq!(a.client, b.client);
    assert_eq!(mock.opened.load(Ordering::Relaxed), 1);
    a.reply("203.0.113.7:3478", b"A reply").await;
    f.packet("203.0.113.7:3478", b"A reply").await;
    assert_eq!(f.stats.connections.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn unsolicited_peer_and_changed_port_keep_true_source_and_session_alive() {
    let mut mock = Mock::new("p").await;
    let mut f = Fixture::new(config(vec![mock.proxy.clone()]));
    f.send("p", "203.0.113.7:3478", b"A").unwrap();
    let a = mock.frame().await;
    for (source, data) in [
        ("198.51.100.9:3097", &b"new peer"[..]),
        ("198.51.100.9:4000", &b"new port"[..]),
        ("203.0.113.7:3478", &b"A still works"[..]),
    ] {
        a.reply(source, data).await;
        f.packet(source, data).await;
    }
    f.send("p", "198.51.100.9:3097", b"reply to B").unwrap();
    let b = mock.frame().await;
    assert_eq!(b.association, a.association);
    assert_eq!(b.target, "198.51.100.9:3097".parse().unwrap());
    assert_eq!(f.stats.activity.snapshots().len(), 3);
    assert_eq!(mock.opened.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn incoming_and_outgoing_cannot_bypass_block_direct_other_proxy_or_dns() {
    let mut mock = Mock::new("p").await;
    let mut other = Mock::new("q").await;
    let mut c = config(vec![mock.proxy.clone(), other.proxy.clone()]);
    for (id, network, action) in [
        ("block", "198.51.100.2/32", Action::Block),
        ("direct", "198.51.100.3/32", Action::Direct),
        ("other", "198.51.100.4/32", Action::Proxy("q".into())),
    ] {
        c.rules.push(serde_json::from_value(serde_json::json!({"id":id,"name":id,"enabled":true,"networks":[network],"action":action})).unwrap());
    }
    let mut f = Fixture::new(c);
    f.send("p", "203.0.113.7:3478", b"A").unwrap();
    let a = mock.frame().await;
    for source in [
        "198.51.100.2:3097",
        "198.51.100.3:3097",
        "198.51.100.4:3097",
        "203.0.113.7:53",
        "[2001:db8::1]:3097",
    ] {
        a.reply(source, b"must not inject").await;
    }
    a.reply("203.0.113.7:3478", b"marker").await;
    f.packet("203.0.113.7:3478", b"marker").await;
    assert!(f.packets.try_recv().is_err());
    for target in [
        "198.51.100.2:3097",
        "198.51.100.3:3097",
        "198.51.100.4:3097",
        "203.0.113.7:53",
    ] {
        assert!(f.send("p", target, b"must not proxy").is_err());
    }
    f.send("q", "198.51.100.4:3097", b"Q").unwrap();
    let q = other.frame().await;
    assert_eq!(q.payload, b"Q");
    assert_ne!(q.client, a.client);
    q.reply("198.51.100.4:3097", b"Q reply").await;
    f.packet("198.51.100.4:3097", b"Q reply").await;
    assert!(f.stats.blocked.load(Ordering::Relaxed) >= 9);
}

#[tokio::test]
async fn socket_reuse_and_close_invalidate_old_association_without_touching_other_sockets() {
    let mut mock = Mock::new("p").await;
    let mut f = Fixture::new(config(vec![mock.proxy.clone()]));
    f.send("p", "203.0.113.7:3478", b"old").unwrap();
    let old = mock.frame().await;
    f.generation.store(1, Ordering::Release);
    f.socket.generation = (1, 0, 0);
    f.send("p", "203.0.113.7:3478", b"new").unwrap();
    let new = mock.frame().await;
    assert_ne!(old.association, new.association);
    old.reply("198.51.100.9:3097", b"stale").await;
    new.reply("198.51.100.9:3097", b"current").await;
    f.packet("198.51.100.9:3097", b"current").await;
    assert!(f.packets.try_recv().is_err());
    let mut local = f.socket;
    local.local = "192.0.2.10:3098".parse().unwrap();
    f.pool
        .send(
            local,
            Owner {
                name: "game.exe",
                path: "C:\\Games\\game.exe",
            },
            "p",
            Outgoing {
                destination: "203.0.113.7:3478".parse().unwrap(),
                payload: b"other socket",
                address: 42,
                stamp: 0,
            },
        )
        .unwrap();
    let separate = mock.frame().await;
    assert_ne!(new.association, separate.association);
}

#[tokio::test]
async fn ipv6_new_peer_is_reinjected_into_the_original_ipv6_socket() {
    let mut mock = Mock::new("p").await;
    let mut f = Fixture::new(config(vec![mock.proxy.clone()]));
    f.socket.local = "[2001:db8::10]:3097".parse().unwrap();
    f.send("p", "[2001:db8::7]:3478", b"v6").unwrap();
    let a = mock.frame().await;
    a.reply("[2001:db8::9]:4000", b"v6 peer").await;
    f.packet("[2001:db8::9]:4000", b"v6 peer").await;
}

#[tokio::test]
async fn dropping_pool_closes_records_and_counters() {
    let mut mock = Mock::new("p").await;
    let mut f = Fixture::new(config(vec![mock.proxy.clone()]));
    f.send("p", "203.0.113.7:3478", b"A").unwrap();
    let a = mock.frame().await;
    a.reply("198.51.100.9:3097", b"B").await;
    f.packet("198.51.100.9:3097", b"B").await;
    let stats = f.stats.clone();
    drop(f);
    timeout(Duration::from_secs(3), async {
        while stats.connections.load(Ordering::Relaxed) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        stats
            .activity
            .snapshots()
            .iter()
            .all(|s| s.status.finished())
    );
}

#[tokio::test]
async fn dns_expiration_and_unknown_peers_follow_direct_without_destroying_allowed_peers() {
    let mut mock = Mock::new("p").await;
    let mut c = config(vec![mock.proxy.clone()]);
    c.default_action = Action::Direct;
    c.rules.push(serde_json::from_value(serde_json::json!({"id":"domains","name":"domains","enabled":true,"process_names":["game.exe"],"domain_suffixes":["proxy.test"],"action":{"kind":"proxy","proxy_id":"p"}})).unwrap());
    let mut f = Fixture::new(c);
    f.observe_name("203.0.113.7", "a.proxy.test", 1);
    f.send("p", "203.0.113.7:3478", b"A").unwrap();
    let a = mock.frame().await;
    a.reply("198.51.100.9:3097", b"unknown name").await;
    a.reply("203.0.113.7:3478", b"A allowed").await;
    f.packet("203.0.113.7:3478", b"A allowed").await;
    assert!(f.packets.try_recv().is_err());
    f.observe_name("198.51.100.9", "b.proxy.test", 60);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    a.reply("203.0.113.7:3478", b"expired A").await;
    a.reply("198.51.100.9:3097", b"B now allowed").await;
    f.packet("198.51.100.9:3097", b"B now allowed").await;
    assert!(f.packets.try_recv().is_err());
    assert!(f.send("p", "203.0.113.7:3478", b"must go direct").is_err());
    f.pool.forget(f.socket, "203.0.113.7:3478".parse().unwrap());
    f.send("p", "198.51.100.9:3097", b"B survives").unwrap();
    let b = mock.frame().await;
    assert_eq!(a.association, b.association);
    assert_eq!(mock.opened.load(Ordering::Relaxed), 1);
    assert!(
        f.stats
            .activity
            .snapshots()
            .iter()
            .any(|s| s.info.destination == a.target && s.status == Status::Closed)
    );
}

#[tokio::test]
async fn a_new_dns_block_retires_only_its_peer() {
    let mut mock = Mock::new("p").await;
    let mut c = config(vec![mock.proxy.clone()]);
    c.rules.push(serde_json::from_value(serde_json::json!({"id":"blocked","name":"blocked","enabled":true,"domains":["blocked.test"],"action":{"kind":"block"}})).unwrap());
    let mut f = Fixture::new(c);
    f.send("p", "203.0.113.7:3478", b"A").unwrap();
    f.send("p", "198.51.100.9:3097", b"B").unwrap();
    let a = mock.frame().await;
    let b = mock.frame().await;
    f.observe_name("203.0.113.7", "blocked.test", 60);
    f.pool.forget(f.socket, a.target);
    a.reply("203.0.113.7:3478", b"blocked A").await;
    b.reply("198.51.100.9:3097", b"B allowed").await;
    f.packet("198.51.100.9:3097", b"B allowed").await;
    assert!(f.packets.try_recv().is_err());
    assert!(f.send("p", "203.0.113.7:3478", b"blocked send").is_err());
    f.send("p", "198.51.100.9:3097", b"B still works").unwrap();
    assert_eq!(mock.frame().await.association, a.association);
    assert_eq!(f.stats.connections.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn malformed_datagram_does_not_close_the_shared_association() {
    let mut mock = Mock::new("p").await;
    let mut f = Fixture::new(config(vec![mock.proxy.clone()]));
    f.send("p", "203.0.113.7:3478", b"A").unwrap();
    let a = mock.frame().await;
    a.relay.send_to(&[0, 0, 1, 1], a.client).await.unwrap();
    a.reply("198.51.100.9:3097", b"valid after malformed").await;
    f.packet("198.51.100.9:3097", b"valid after malformed")
        .await;
    assert!(f.stats.blocked.load(Ordering::Relaxed) > 0);
}

#[tokio::test]
async fn control_failure_is_reported_and_the_next_send_creates_a_new_association() {
    let mut mock = Mock::new("p").await;
    let mut f = Fixture::new(config(vec![mock.proxy.clone()]));
    f.send("p", "203.0.113.7:3478", b"A").unwrap();
    let a = mock.frame().await;
    a.reply("203.0.113.7:3478", b"before failure").await;
    f.packet("203.0.113.7:3478", b"before failure").await;
    a.stop.send(()).unwrap();
    timeout(Duration::from_secs(3), async {
        while f.stats.connections.load(Ordering::Relaxed) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(f.stats.activity.snapshots()[0].status, Status::Failed);
    f.pool.cleanup();
    f.send("p", "203.0.113.7:3478", b"retry").unwrap();
    let new = mock.frame().await;
    assert_ne!(new.association, a.association);
    new.reply("198.51.100.9:3097", b"after retry").await;
    f.packet("198.51.100.9:3097", b"after retry").await;
}

#[test]
fn peer_limits_and_idle_expiry_release_records_and_slots() {
    let proxy = Proxy {
        id: "p".into(),
        name: "p".into(),
        host: "127.0.0.1".into(),
        port: 1,
        username: String::new(),
        protected_password: None,
    };
    let stats = Arc::new(Statistics::default());
    let shared = Arc::new(Shared {
        context: Context {
            config: Arc::new(config(vec![proxy])),
            domains: Arc::default(),
            stats: stats.clone(),
            inject: Arc::new(|_: Vec<u8>, _: u64| Ok(())),
            valid: Arc::new(|_, _| true),
        },
        memory: Arc::new(Semaphore::new(4096)),
        peers: Arc::new(Semaphore::new(MAX_PEERS)),
        domain_rules: false,
    });
    let mut state = State {
        key: Key {
            pid: 1,
            local: "192.0.2.1:3097".parse().unwrap(),
            proxy: "p".into(),
        },
        socket: SocketId {
            pid: 1,
            local: "192.0.2.1:3097".parse().unwrap(),
            generation: (0, 0, 0),
        },
        name: "game.exe".into(),
        path: String::new(),
        shared: shared.clone(),
        peers: HashMap::new(),
        address: 42,
        stamp: 0,
        last: Instant::now(),
        alive: Arc::new(AtomicBool::new(true)),
    };
    for port in 1..=MAX_PEERS_PER_ASSOCIATION {
        assert!(state.peer(
            SocketAddr::new("203.0.113.1".parse().unwrap(), port as u16),
            0,
            Status::Active
        ));
    }
    assert!(!state.peer("203.0.113.2:3097".parse().unwrap(), 0, Status::Active));
    assert_eq!(
        stats.connections.load(Ordering::Relaxed),
        MAX_PEERS_PER_ASSOCIATION as u64
    );
    assert!(state.expire(Instant::now() + IDLE + Duration::from_secs(1)));
    assert_eq!(stats.connections.load(Ordering::Relaxed), 0);
    assert_eq!(shared.peers.available_permits(), MAX_PEERS);
}

#[cfg(windows)]
#[tokio::test]
async fn close_preserves_a_truly_new_association_but_invalidates_its_current_birth() {
    use crate::platform::windows::{divert::SocketClose, monitor::SocketGenerations};
    let mut mock = Mock::new("p").await;
    let mut f = Fixture::new(config(vec![mock.proxy.clone()]));
    f.stamp = 200;
    let generations = SocketGenerations::default();
    let flow = FlowKey {
        source: f.socket.local,
        destination: "203.0.113.7:3478".parse().unwrap(),
    };
    f.socket.generation = generations.stamp(f.socket.pid, flow, false);
    let observe = generations.clone();
    Arc::get_mut(&mut f.pool.shared).unwrap().context.valid = Arc::new(move |id, birth| {
        observe.valid(
            id.pid,
            FlowKey {
                source: id.local,
                destination: id.local,
            },
            birth,
            id.generation,
        )
    });
    f.send("p", "203.0.113.7:3478", b"new owner").unwrap();
    let a = mock.frame().await;
    let mut close = SocketClose {
        pid: 122,
        source: "0.0.0.0:3097".parse().unwrap(),
        destination: "0.0.0.0:0".parse().unwrap(),
        tcp: false,
        stamp: 100,
    };
    generations.closed(&close);
    a.reply("198.51.100.9:3097", b"survives other PID CLOSE")
        .await;
    f.packet("198.51.100.9:3097", b"survives other PID CLOSE")
        .await;
    close.pid = f.socket.pid;
    generations.closed(&close);
    a.reply(
        "198.51.100.9:4000",
        b"new birth survives old same-PID CLOSE",
    )
    .await;
    f.packet(
        "198.51.100.9:4000",
        b"new birth survives old same-PID CLOSE",
    )
    .await;
    f.socket.generation = generations.stamp(f.socket.pid, flow, false);
    f.send("p", "203.0.113.7:3478", b"keep same relay").unwrap();
    assert_eq!(mock.frame().await.association, a.association);
    close.stamp = 300;
    generations.closed(&close);
    a.reply("198.51.100.9:4000", b"after current CLOSE").await;
    timeout(Duration::from_secs(3), async {
        while f.stats.connections.load(Ordering::Relaxed) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(f.packets.try_recv().is_err());
    assert_eq!(mock.opened.load(Ordering::Relaxed), 1);
}

#[cfg(windows)]
#[tokio::test]
async fn delayed_close_invalidates_an_existing_old_association_after_port_reuse() {
    use crate::platform::windows::{divert::SocketClose, monitor::SocketGenerations};
    let mut mock = Mock::new("p").await;
    let mut f = Fixture::new(config(vec![mock.proxy.clone()]));
    let generations = SocketGenerations::default();
    let flow = FlowKey {
        source: f.socket.local,
        destination: "203.0.113.7:3478".parse().unwrap(),
    };
    f.stamp = 100;
    f.socket.generation = generations.stamp(f.socket.pid, flow, false);
    let observe = generations.clone();
    Arc::get_mut(&mut f.pool.shared).unwrap().context.valid = Arc::new(move |id, birth| {
        observe.valid(
            id.pid,
            FlowKey {
                source: id.local,
                destination: id.local,
            },
            birth,
            id.generation,
        )
    });
    f.send("p", "203.0.113.7:3478", b"S1").unwrap();
    let old = mock.frame().await;
    f.stamp = 200;
    f.socket.generation = generations.stamp(f.socket.pid, flow, false);
    f.send("p", "198.51.100.9:3097", b"S2 before delayed CLOSE")
        .unwrap();
    let before_close = mock.frame().await;
    assert_eq!(old.association, before_close.association);
    generations.closed(&SocketClose {
        pid: f.socket.pid,
        source: "0.0.0.0:3097".parse().unwrap(),
        destination: "0.0.0.0:0".parse().unwrap(),
        tcp: false,
        stamp: 150,
    });
    old.reply("203.0.113.7:3478", b"stale S1 response").await;
    assert!(
        timeout(Duration::from_millis(500), f.packets.recv())
            .await
            .is_err(),
        "old association survived its CLOSE and injected into the reused port"
    );
    f.socket.generation = generations.stamp(f.socket.pid, flow, false);
    f.send("p", "198.51.100.9:3097", b"S2 after delayed CLOSE")
        .unwrap();
    let new = mock.frame().await;
    assert_ne!(old.association, new.association);
    new.reply("198.51.100.9:3097", b"S2 response").await;
    f.packet("198.51.100.9:3097", b"S2 response").await;
}
