use super::{
    divert::{Device, Driver},
    monitor::{SocketGenerations, SocketMonitor},
    process,
};
use crate::{
    config::{Action, Config, Protocol},
    connections::{Connection, Info, Status},
    dns::{self, DomainCache},
    engine::{FailureHandler, LogLevel, LogSource, Statistics},
    packet::{FlowKey, Packet},
    rules::{self, Flow},
    socks,
    udp::{self, Outgoing, Owner, Pool, SocketId},
};
use anyhow::{Context, Result};
use ipnet::IpNet;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpStream},
    runtime::Runtime,
    time::timeout,
};

const MAX_FLOWS: usize = 4096;
const MAX_LOCAL_MISSES: usize = 256;
const LOCAL_MISS_TTL: Duration = Duration::from_secs(2);
type NatTable = Arc<Mutex<NatMaps>>;

#[derive(Default)]
struct NatMaps {
    reflected: HashMap<FlowKey, Nat>,
    original: HashMap<FlowKey, FlowKey>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configured_local_admission_preserves_tracking_and_survives_unknown_owner_or_full_cache() {
        let networks = ["198.51.100.0/24", "2001:db8:10::/48"].map(|range| range.parse().unwrap());
        let mut misses = LocalAttributionMisses::new(&networks);
        let now = Instant::now();
        for destination in ["198.51.100.1:445", "[2001:db8:10::1]:443"] {
            let source = if destination.starts_with('[') {
                "[2001:db8::30]:5000"
            } else {
                "192.0.2.30:5000"
            };
            let flow = FlowKey {
                source: source.parse().unwrap(),
                destination: destination.parse().unwrap(),
            };
            let known = misses.classify(flow, true, false, now, |attempts| {
                assert_eq!(attempts, 1, "Local attribution must not sleep or retry");
                Some(process::Process {
                    pid: 4,
                    name: "System".into(),
                    path: String::new(),
                })
            });
            assert!(
                matches!(
                    known,
                    NewFlowOwner::Identified(process::Process { pid: 4, .. })
                ),
                "Known local flows retain normal connection tracking"
            );
            for tcp in [true, false] {
                assert!(matches!(
                    misses.classify(flow, tcp, false, now, |_| None),
                    NewFlowOwner::LocalDirect
                ));
                assert!(matches!(
                    misses.classify(flow, tcp, true, now, |_| panic!(
                        "A full cache must not query ownership"
                    )),
                    NewFlowOwner::LocalDirect
                ));
            }
        }
        for destination in [
            "192.168.50.1:445",
            "[fd00::1]:443",
            "203.0.113.1:445",
            "[2001:db8::1]:443",
        ] {
            let flow = FlowKey {
                source: "192.0.2.30:5000".parse().unwrap(),
                destination: destination.parse().unwrap(),
            };
            assert!(matches!(
                misses.classify(flow, true, false, now, |attempts| {
                    assert_eq!(
                        attempts, 3,
                        "Non-local attribution retains its retry policy"
                    );
                    None
                }),
                NewFlowOwner::Unknown
            ));
            assert!(matches!(
                misses.classify(flow, true, true, now, |_| panic!(
                    "A full cache must not query ownership"
                )),
                NewFlowOwner::Capacity
            ));
            assert!(matches!(
                misses.classify(flow, true, false, now, |_| Some(process::Process {
                    pid: 4,
                    name: "System".into(),
                    path: String::new()
                })),
                NewFlowOwner::Identified(_)
            ));
        }
    }

    #[test]
    fn local_attribution_misses_skip_repeated_queries_until_ttl_then_restore_tracking() {
        let networks = crate::local_network::default_networks();
        let mut misses = LocalAttributionMisses::new(&networks);
        let now = Instant::now();
        let flow = FlowKey {
            source: "192.0.2.30:5000".parse().unwrap(),
            destination: "192.168.50.1:445".parse().unwrap(),
        };
        assert!(matches!(
            misses.classify(flow, true, false, now, |attempts| {
                assert_eq!(attempts, 1);
                None
            }),
            NewFlowOwner::LocalDirect
        ));
        for _ in 0..100 {
            assert!(matches!(
                misses.classify(flow, true, false, now + Duration::from_secs(1), |_| panic!(
                    "Repeated local packets must not query IP Helper"
                )),
                NewFlowOwner::LocalDirect
            ));
        }
        // TCP and UDP sharing an endpoint/peer have independent attribution.
        assert!(matches!(
            misses.classify(flow, false, false, now, |attempts| {
                assert_eq!(attempts, 1);
                None
            }),
            NewFlowOwner::LocalDirect
        ));
        let retried = misses.classify(flow, true, false, now + LOCAL_MISS_TTL, |attempts| {
            assert_eq!(attempts, 1);
            Some(process::Process {
                pid: 42,
                name: "app.exe".into(),
                path: String::new(),
            })
        });
        assert!(matches!(
            retried,
            NewFlowOwner::Identified(process::Process { pid: 42, .. })
        ));
        assert!(!misses.expires.contains_key(&(flow, true)));
    }

    #[test]
    fn local_attribution_miss_cache_is_bounded_expires_and_never_caches_public_addresses() {
        let networks = crate::local_network::default_networks();
        let mut misses = LocalAttributionMisses::new(&networks);
        let now = Instant::now();
        let mut flow = FlowKey {
            source: "192.0.2.30:5000".parse().unwrap(),
            destination: "192.168.50.1:445".parse().unwrap(),
        };
        for port in 10000..10000 + MAX_LOCAL_MISSES as u16 + 1 {
            flow.source.set_port(port);
            assert!(matches!(
                misses.classify(flow, true, false, now, |_| None),
                NewFlowOwner::LocalDirect
            ));
            assert!(misses.expires.len() <= MAX_LOCAL_MISSES);
        }
        assert_eq!(misses.expires.len(), MAX_LOCAL_MISSES);
        assert!(matches!(
            misses.classify(flow, true, false, now, |_| panic!(
                "Most recent miss stays cached"
            )),
            NewFlowOwner::LocalDirect
        ));
        flow.source.set_port(20000);
        assert!(matches!(
            misses.classify(flow, true, false, now + LOCAL_MISS_TTL, |_| None),
            NewFlowOwner::LocalDirect
        ));
        assert_eq!(misses.expires.len(), 1);
        flow.destination = "203.0.113.1:445".parse().unwrap();
        for _ in 0..2 {
            assert!(matches!(
                misses.classify(flow, true, false, now, |attempts| {
                    assert_eq!(attempts, 3);
                    None
                }),
                NewFlowOwner::Unknown
            ));
        }
        assert_eq!(misses.expires.len(), 1);
        assert!(
            misses
                .expires
                .keys()
                .all(|(flow, _)| crate::local_network::contains(&networks, flow.destination.ip()))
        );
    }

    #[test]
    fn idle_direct_tcp_lifetime_uses_socket_owners_independently_of_the_journal() {
        let stats = Arc::new(Statistics::default());
        stats.activity.set_tracking(true);
        let flow = FlowKey {
            source: "192.0.2.1:5000".parse().unwrap(),
            destination: "203.0.113.1:443".parse().unwrap(),
        };
        let record = stats
            .activity
            .start(
                Info {
                    pid: 10,
                    process: "game.exe".into(),
                    source: flow.source,
                    destination: flow.destination,
                    protocol: Protocol::Tcp,
                    route: "Direct".into(),
                    detail: String::new(),
                    action: Action::Direct,
                    stamp: 0,
                },
                Status::Active,
            )
            .unwrap();
        let now = Instant::now();
        let decision = Decision {
            xray_generation: None,
            action: Action::Direct,
            last: now,
            stamp: (0, 0, 0),
            initial_sequence: 0,
            owner: process::Process {
                pid: 10,
                name: "game.exe".into(),
                path: String::new(),
            },
            dns_check: now,
            record: Some(record.clone()),
        };
        let live = HashMap::from([(flow, 10)]);
        let closed = HashMap::new();
        assert!(decision.keep(
            flow,
            true,
            &NatMaps::default(),
            now + Duration::from_secs(3600),
            Some(&live)
        ));
        stats.activity.set_tracking(false);
        assert_eq!(record.status(), Status::Active);
        assert!(
            decision.keep(
                flow,
                true,
                &NatMaps::default(),
                now + Duration::from_secs(3600),
                Some(&live)
            ),
            "Hiding the journal must not change routing lifetime"
        );
        let mut decision = decision;
        decision.record = None;
        assert!(
            decision.keep(
                flow,
                true,
                &NatMaps::default(),
                now + Duration::from_secs(3600),
                Some(&live)
            ),
            "A live socket may be omitted when the monitor reaches its capacity"
        );
        assert!(!decision.keep(
            flow,
            true,
            &NatMaps::default(),
            now + Duration::from_secs(3600),
            Some(&closed)
        ));
        assert!(
            !decision.keep(
                flow,
                true,
                &NatMaps::default(),
                now + Duration::from_secs(3600),
                Some(&HashMap::from([(flow, 11)]))
            ),
            "A reused tuple belongs to a different process"
        );
        assert!(
            decision.keep(
                flow,
                true,
                &NatMaps::default(),
                now + Duration::from_secs(3600),
                None
            ),
            "Failed IP Helper snapshots preserve established routing"
        );
        assert!(decision.keep(
            flow,
            true,
            &NatMaps::default(),
            now + Duration::from_secs(10),
            Some(&closed)
        ));
    }
    #[tokio::test]
    async fn tcp_relay_lifecycle_has_one_record_for_success_or_socks_rejection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for reject in [false, true] {
            let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_port = proxy_listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let (mut stream, _) = proxy_listener.accept().await.unwrap();
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                stream.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 10];
                stream.read_exact(&mut request).await.unwrap();
                stream
                    .write_all(&[5, if reject { 5 } else { 0 }, 0, 1, 127, 0, 0, 1, 0, 1])
                    .await
                    .unwrap();
                if !reject {
                    let mut hello = [0; 5];
                    stream.read_exact(&mut hello).await.unwrap();
                    assert_eq!(&hello, b"hello");
                    stream.write_all(b"world").await.unwrap();
                    stream.shutdown().await.unwrap();
                }
            });
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (local, _) = listener.accept().await.unwrap();
            let stats = Arc::new(Statistics::default());
            if reject {
                stats.activity.set_tracking(true);
                stats.activity.set_only_active(false);
            }
            let flow = FlowKey {
                source: client.local_addr().unwrap(),
                destination: "203.0.113.1:443".parse().unwrap(),
            };
            let record = stats
                .activity
                .start(
                    Info {
                        pid: 1,
                        process: "game.exe".into(),
                        source: flow.source,
                        destination: flow.destination,
                        protocol: Protocol::Tcp,
                        route: "VPN".into(),
                        detail: "Rule".into(),
                        action: Action::Proxy("p".into()),
                        stamp: 0,
                    },
                    Status::Connecting,
                )
                .unwrap();
            let mapping = Nat {
                original: flow,
                proxy_id: "p".into(),
                process: "game.exe".into(),
                last: Instant::now(),
                active: Arc::new(AtomicBool::new(true)),
                record: Some(record.clone()),
            };
            let config = Config {
                proxies: vec![crate::config::Proxy {
                    id: "p".into(),
                    name: "VPN".into(),
                    host: "127.0.0.1".into(),
                    port: proxy_port,
                    username: String::new(),
                    protected_password: None,
                }],
                ..Config::default()
            };
            let counters = stats.clone();
            let worker =
                tokio::spawn(async move { tcp_session(local, &mapping, &config, &counters).await });
            if !reject {
                timeout(Duration::from_secs(3), async {
                    while record.status() == Status::Connecting {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                assert_eq!(record.status(), Status::Active);
                stats.activity.set_tracking(true);
                stats.activity.set_only_active(false);
                assert_eq!(stats.activity.snapshots()[0].status, Status::Active);
                client.write_all(b"hello").await.unwrap();
                client.shutdown().await.unwrap();
                let mut reply = Vec::new();
                timeout(Duration::from_secs(3), client.read_to_end(&mut reply))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(reply, b"world");
            }
            let result = timeout(Duration::from_secs(3), worker)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(result.is_err(), reject);
            server.await.unwrap();
            let rows = stats.activity.snapshots();
            assert_eq!(rows.len(), 1);
            assert_eq!(
                rows[0].status,
                if reject {
                    Status::Failed
                } else {
                    Status::Closed
                }
            );
            assert_eq!(stats.connections.load(Ordering::Relaxed), 0);
        }
    }
    #[test]
    fn idle_live_tcp_connection_survives_cache_cleanup() {
        let original = FlowKey {
            source: "192.0.2.1:51000".parse().unwrap(),
            destination: "203.0.113.1:443".parse().unwrap(),
        };
        let reflected = FlowKey {
            source: "192.0.2.1:40000".parse().unwrap(),
            destination: "203.0.113.1:10001".parse().unwrap(),
        };
        let active = Arc::new(AtomicBool::new(true));
        let now = Instant::now();
        let mut maps = NatMaps::default();
        maps.original.insert(original, reflected);
        maps.reflected.insert(
            reflected,
            Nat {
                original,
                proxy_id: "test".into(),
                process: "test.exe".into(),
                last: now,
                active: active.clone(),
                record: None,
            },
        );
        maps.cleanup(now + Duration::from_secs(3600));
        assert!(maps.original.contains_key(&original));
        active.store(false, Ordering::Relaxed);
        maps.cleanup(now + Duration::from_secs(3600));
        assert!(maps.original.is_empty());
        assert!(maps.reflected.is_empty());
    }
}

impl NatMaps {
    fn cleanup(&mut self, now: Instant) {
        self.reflected.retain(|_, n| {
            n.active.load(Ordering::Relaxed)
                || now.duration_since(n.last) < Duration::from_secs(900)
        });
        self.original
            .retain(|_, reflected| self.reflected.contains_key(reflected));
    }
}

#[derive(Clone)]
struct Nat {
    original: FlowKey,
    proxy_id: String,
    process: String,
    last: Instant,
    active: Arc<AtomicBool>,
    record: Option<Connection>,
}
struct Decision {
    action: Action,
    xray_generation: Option<u64>,
    last: Instant,
    stamp: (u64, u64, u64),
    initial_sequence: u32,
    owner: process::Process,
    dns_check: Instant,
    record: Option<Connection>,
}
impl Decision {
    fn active_mapping(flow: FlowKey, table: &NatMaps) -> bool {
        table
            .original
            .get(&flow)
            .and_then(|key| table.reflected.get(key))
            .is_some_and(|n| n.active.load(Ordering::Relaxed))
    }
    fn keep(
        &self,
        flow: FlowKey,
        tcp: bool,
        table: &NatMaps,
        now: Instant,
        owners: Option<&HashMap<FlowKey, u32>>,
    ) -> bool {
        now.duration_since(self.last) < Duration::from_secs(900)
            || (tcp
                && (Self::active_mapping(flow, table)
                    // A failed owner-table query must not reroute an established
                    // connection. Journal visibility is never socket lifetime.
                    || owners.is_none_or(|owners| owners.get(&flow) == Some(&self.owner.pid))))
    }
}

enum NewFlowOwner {
    Identified(process::Process),
    LocalDirect,
    Capacity,
    Unknown,
}

struct LocalAttributionMisses<'a> {
    networks: &'a [IpNet],
    expires: HashMap<(FlowKey, bool), Instant>,
}

impl<'a> LocalAttributionMisses<'a> {
    fn new(networks: &'a [IpNet]) -> Self {
        Self {
            networks,
            expires: HashMap::new(),
        }
    }

    /// Preserve normal tracking when possible. A short, bounded negative cache
    /// prevents unowned local UDP from querying IP Helper on every datagram.
    fn classify(
        &mut self,
        flow: FlowKey,
        tcp: bool,
        cache_full: bool,
        now: Instant,
        identify: impl FnOnce(usize) -> Option<process::Process>,
    ) -> NewFlowOwner {
        let local = crate::local_network::contains(self.networks, flow.destination.ip());
        if cache_full {
            return if local {
                NewFlowOwner::LocalDirect
            } else {
                NewFlowOwner::Capacity
            };
        }
        let key = (flow, tcp);
        if local {
            if self.expires.get(&key).is_some_and(|expires| now < *expires) {
                return NewFlowOwner::LocalDirect;
            }
            self.expires.remove(&key);
        }
        // Direct local traffic need not wait/retry for attribution; retry later
        // only to restore observability if its owner becomes available.
        match identify(if local { 1 } else { 3 }) {
            Some(owner) => NewFlowOwner::Identified(owner),
            None if local => {
                if self.expires.len() >= MAX_LOCAL_MISSES {
                    self.expires.retain(|_, expires| now < *expires);
                    if self.expires.len() >= MAX_LOCAL_MISSES
                        && let Some(oldest) = self
                            .expires
                            .iter()
                            .min_by_key(|(_, expires)| **expires)
                            .map(|(key, _)| *key)
                    {
                        self.expires.remove(&oldest);
                    }
                }
                self.expires.insert(key, now + LOCAL_MISS_TTL);
                NewFlowOwner::LocalDirect
            }
            None => NewFlowOwner::Unknown,
        }
    }
}

pub struct Network {
    runtime: Option<Runtime>,
    device: Arc<Device>,
    capture: Option<thread::JoinHandle<()>>,
    stopping: Arc<AtomicBool>,
    monitor: Option<SocketMonitor>,
}

impl Network {
    pub fn start(
        mut config: Config,
        stats: Arc<Statistics>,
        failure: FailureHandler,
    ) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        // Resolve proxy hostnames before interception to prevent recursive bootstrap DNS.
        runtime.block_on(async {
            for proxy in &mut config.proxies {
                if proxy.host.parse::<IpAddr>().is_err() {
                    let address = timeout(
                        Duration::from_secs(8),
                        tokio::net::lookup_host((proxy.host.as_str(), proxy.port)),
                    )
                    .await
                    .context("Proxy address resolution timed out")??
                    .next()
                    .context("Could not resolve the proxy's IP address")?;
                    proxy.host = address.ip().to_string();
                }
            }
            Ok::<_, anyhow::Error>(())
        })?;
        let (v4, v6) = runtime.block_on(async {
            Ok::<_, anyhow::Error>((
                TcpListener::bind("0.0.0.0:0").await?,
                TcpListener::bind("[::]:0").await?,
            ))
        })?;
        let port4 = v4.local_addr()?.port();
        let port6 = v6.local_addr()?.port();
        let config = Arc::new(config);
        let nat = NatTable::default();
        let domains = Arc::new(Mutex::new(DomainCache::default()));
        let driver = Driver::load()?;
        let monitor = SocketMonitor::start(driver.open_monitor()?, failure.clone(), stats.clone())?;
        let generations = monitor.generations();
        let activity = stats.activity.clone();
        runtime.spawn(async move {
            let mut timer = tokio::time::interval(Duration::from_secs(5));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                timer.tick().await;
                activity.expire();
            }
        });
        // Opening the driver is the first operation that intercepts real traffic.
        let device = driver.open()?;
        let stopping = Arc::new(AtomicBool::new(false));
        for listener in [v4, v6] {
            runtime.spawn(accept_loop(
                listener,
                nat.clone(),
                config.clone(),
                stats.clone(),
            ));
        }
        let worker_device = device.clone();
        let worker_stats = stats.clone();
        let worker_stopping = stopping.clone();
        let handle = runtime.handle().clone();
        let capture = thread::Builder::new()
            .name("packet-router".into())
            .spawn(move || {
                let result = capture(CaptureContext {
                    device: worker_device,
                    stats: worker_stats.clone(),
                    stopping: worker_stopping.clone(),
                    config,
                    nat,
                    domains,
                    runtime: handle,
                    port4,
                    port6,
                    generations,
                });
                if let Err(error) = result
                    && !worker_stopping.load(Ordering::Acquire)
                {
                    worker_stats.log(
                        LogSource::Backend,
                        LogLevel::Error,
                        "",
                        "",
                        "",
                        format!("{error:#}"),
                    );
                    failure(format!("Traffic interception stopped: {error:#}"));
                }
            })?;
        Ok(Self {
            runtime: Some(runtime),
            device,
            capture: Some(capture),
            stopping,
            monitor: Some(monitor),
        })
    }
    pub fn stop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        self.device.shutdown();
        if let Some(thread) = self.capture.take() {
            let _ = thread.join();
        }
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(Duration::from_secs(1));
        }
        drop(self.monitor.take());
    }
}
impl Drop for Network {
    fn drop(&mut self) {
        self.stop();
    }
}

struct CaptureContext {
    device: Arc<Device>,
    stats: Arc<Statistics>,
    stopping: Arc<AtomicBool>,
    config: Arc<Config>,
    nat: NatTable,
    domains: Arc<Mutex<DomainCache>>,
    runtime: tokio::runtime::Handle,
    port4: u16,
    port6: u16,
    generations: SocketGenerations,
}

fn capture(context: CaptureContext) -> Result<()> {
    let CaptureContext {
        device,
        stats,
        stopping,
        config,
        nat,
        domains,
        runtime,
        port4,
        port6,
        generations,
    } = context;
    let mut buffer = vec![0u8; 65575];
    let mut decisions: HashMap<(FlowKey, bool), Decision> = HashMap::new();
    let mut local_misses = LocalAttributionMisses::new(&config.local_networks);
    let inject_device = device.clone();
    let socket_generations = generations.clone();
    let mut udp = Pool::new(
        udp::Context {
            config: config.clone(),
            domains: domains.clone(),
            stats: stats.clone(),
            inject: Arc::new(move |bytes, address| inject_device.inject(bytes, address)),
            valid: Arc::new(move |socket, birth| {
                socket_generations.valid(
                    socket.pid,
                    FlowKey {
                        source: socket.local,
                        destination: socket.local,
                    },
                    birth,
                    socket.generation,
                )
            }),
        },
        runtime.clone(),
    );
    let mut dns_flows = HashMap::<(FlowKey, bool), Instant>::new();
    let mut tcp_dns = HashMap::<FlowKey, dns::TcpDnsBuffer>::new();
    let has_domain_rules = config
        .rules
        .iter()
        .any(|rule| rule.enabled && (!rule.domains.is_empty() || !rule.domain_suffixes.is_empty()));
    let mut synthetic = 10000u16;
    let mut cleanup = Instant::now();
    let mut last_lookup_error = Instant::now() - Duration::from_secs(10);
    loop {
        let (length, mut address) = match device.recv(&mut buffer) {
            Ok(value) => value,
            Err(_) if stopping.load(Ordering::Acquire) => break,
            Err(error) => return Err(error),
        };
        if stopping.load(Ordering::Acquire) {
            continue;
        }
        let bytes = &mut buffer[..length];
        let packet = match Packet::parse(bytes) {
            Ok(packet) => packet,
            Err(_) => {
                stats.blocked.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        if !address.outbound() {
            // Only observe replies for a DNS flow we previously allowed directly.
            let reverse = FlowKey {
                source: packet.flow.destination,
                destination: packet.flow.source,
            };
            if dns_flows.contains_key(&(reverse, packet.protocol == Protocol::Tcp)) {
                if packet.protocol == Protocol::Udp {
                    domains.lock().unwrap().observe(packet.payload(bytes));
                } else {
                    if packet.tcp_flags & 2 != 0 && tcp_dns.len() < 128 {
                        tcp_dns.entry(reverse).or_insert_with(|| {
                            dns::TcpDnsBuffer::with_sequence(packet.tcp_sequence.wrapping_add(1))
                        });
                    }
                    if let Some(stream) = tcp_dns.get_mut(&reverse) {
                        for message in stream.feed(packet.tcp_sequence, packet.payload(bytes)) {
                            domains.lock().unwrap().observe(&message);
                        }
                    }
                }
            }
            device.send(bytes, &address)?;
            continue;
        }
        if packet.is_dhcp_client_request(bytes) {
            // Interface configuration must work before the client has an IP or
            // an IP Helper owner, even when the ordinary flow cache is full.
            // Keep this narrow: validated DHCP client messages, never all LAN,
            // all System traffic, or every UDP datagram to a DHCP server port.
            device.send(bytes, &address)?;
            continue;
        }
        if packet.flow.destination.port() == 53 {
            // Keep DNS completely with Windows, including unknown/protected owners.
            // Remember only bounded flow metadata for passive domain observation.
            let key = (packet.flow, packet.protocol == Protocol::Tcp);
            if dns_flows.contains_key(&key) || dns_flows.len() < 512 {
                dns_flows.insert(key, Instant::now());
            }
            if packet.is_syn() {
                tcp_dns.remove(&packet.flow);
            }
            device.send(bytes, &address)?;
            continue;
        }
        // Reflected listener replies are translated back into the application's original tuple.
        if packet.protocol == Protocol::Tcp
            && (packet.flow.source.port() == port4 || packet.flow.source.port() == port6)
        {
            let reflected = {
                let mut table = nat.lock().unwrap();
                table.reflected.get_mut(&packet.flow).map(|n| {
                    n.last = Instant::now();
                    n.clone()
                })
            };
            if let Some(n) = reflected {
                packet.reflect_tcp(
                    bytes,
                    n.original.destination.port(),
                    n.original.source.port(),
                );
                device.reflect(bytes, &mut address)?;
                continue;
            }
        }
        let now = Instant::now();
        if cleanup.elapsed() > Duration::from_secs(15) {
            let idle_tcp: HashSet<_> = {
                let mut table = nat.lock().unwrap();
                table.cleanup(now);
                decisions
                    .iter()
                    .filter_map(|((flow, tcp), decision)| {
                        (*tcp
                            && now.duration_since(decision.last) >= Duration::from_secs(900)
                            && !Decision::active_mapping(*flow, &table))
                        .then_some(*flow)
                    })
                    .collect()
            };
            // One batch per address family only when idle TCP decisions need
            // pruning. Do not hold NAT's mutex across IP Helper calls.
            let tcp_owners = if idle_tcp.is_empty() {
                None
            } else {
                process::tcp_snapshot(&idle_tcp).ok()
            };
            {
                let table = nat.lock().unwrap();
                decisions.retain(|(flow, tcp), decision| {
                    let keep = decision.keep(*flow, *tcp, &table, now, tcp_owners.as_ref());
                    if *tcp
                        && !keep
                        && let Some(record) = &decision.record
                        && !record.status().finished()
                    {
                        record.finish(Status::Closed, "Socket no longer present");
                    }
                    keep
                });
            }
            udp.cleanup();
            dns_flows.retain(|_, last| now.duration_since(*last) < Duration::from_secs(120));
            tcp_dns.retain(|flow, _| dns_flows.contains_key(&(*flow, true)));
            cleanup = now;
        }
        let tcp = packet.protocol == Protocol::Tcp;
        let key = (packet.flow, tcp);
        let mut stamp = if tcp {
            (0, 0, 0)
        } else {
            decisions
                .get(&key)
                .map(|d| generations.stamp(d.owner.pid, packet.flow, false))
                .unwrap_or((0, 0, 0))
        };
        if decisions.get(&key).is_some_and(|d| {
            d.stamp != stamp
                || (tcp && packet.is_syn() && d.initial_sequence != packet.tcp_sequence)
                || d.xray_generation
                    .is_some_and(|generation| generation != stats.xray_bypass.generation())
        }) {
            if let Some(d) = decisions.remove(&key)
                && let Some(record) = d.record
            {
                record.finish(Status::Closed, "New connection on the same endpoints");
            }
            udp.cleanup();
            let mut table = nat.lock().unwrap();
            if let Some(reflected) = table.original.remove(&packet.flow) {
                table.reflected.remove(&reflected);
            }
        }
        let action = if let Some(d) = decisions.get_mut(&key) {
            d.last = now;
            if !tcp
                && has_domain_rules
                && d.owner.pid != std::process::id()
                && d.xray_generation.is_none()
                && now.duration_since(d.dns_check) >= Duration::from_secs(1)
            {
                d.dns_check = now;
                let names = domains.lock().unwrap().lookup(packet.flow.destination.ip());
                let action = rules::resolve(
                    &config,
                    &Flow {
                        process_name: &d.owner.name,
                        process_path: &d.owner.path,
                        destination: packet.flow.destination,
                        protocol: packet.protocol,
                        domains: &names,
                    },
                );
                if d.action != action {
                    udp.forget(
                        SocketId {
                            pid: d.owner.pid,
                            local: packet.flow.source,
                            generation: d.stamp,
                        },
                        packet.flow.destination,
                    );
                    if let Some(old) = d.record.take() {
                        old.finish(Status::Closed, "Route changed");
                    }
                    let observe = match &action {
                        Action::Direct => true,
                        Action::Block => stats.activity.tracking(),
                        Action::Proxy(_) => false,
                    };
                    if observe || stats.log_tracking() {
                        let route = match &action {
                            Action::Direct => "Direct".into(),
                            Action::Block => "Block".into(),
                            Action::Proxy(id) => config
                                .proxy(id)
                                .map(|proxy| proxy.name.clone())
                                .unwrap_or_else(|_| "Proxy not found".into()),
                        };
                        let detail = format!("UDP · Route updated using DNS: {}", names.join(", "));
                        stats.log(
                            LogSource::Connections,
                            LogLevel::Verbose,
                            &d.owner.name,
                            packet.flow.destination.to_string(),
                            &route,
                            &detail,
                        );
                        if observe {
                            let info = Info {
                                pid: d.owner.pid,
                                process: d.owner.name.clone(),
                                source: packet.flow.source,
                                destination: packet.flow.destination,
                                protocol: Protocol::Udp,
                                route,
                                detail,
                                action: action.clone(),
                                stamp: address.timestamp(),
                            };
                            if action == Action::Block {
                                stats.activity.completed(info, Status::Blocked);
                            } else if action == Action::Direct {
                                d.record = stats.activity.start(info, Status::Active);
                            }
                        }
                    }
                    d.action = action;
                }
            }
            d.action.clone()
        } else {
            let owner = match local_misses.classify(
                packet.flow,
                tcp,
                decisions.len() >= MAX_FLOWS,
                now,
                |attempts| {
                    (0..attempts).find_map(|attempt| {
                        let result = process::identify(packet.flow, packet.protocol).ok();
                        if result.is_none() && attempt + 1 < attempts {
                            thread::sleep(Duration::from_millis(1));
                        }
                        result
                    })
                },
            ) {
                NewFlowOwner::Identified(owner) => owner,
                NewFlowOwner::LocalDirect => {
                    device.send(bytes, &address)?;
                    continue;
                }
                NewFlowOwner::Capacity => {
                    stats.blocked.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                NewFlowOwner::Unknown => {
                    stats.blocked.fetch_add(1, Ordering::Relaxed);
                    if last_lookup_error.elapsed() > Duration::from_secs(5) {
                        stats.log(
                            LogSource::Connections,
                            LogLevel::Error,
                            "Unknown process",
                            packet.flow.destination.to_string(),
                            "Block",
                            "Could not identify the connection owner reliably",
                        );
                        last_lookup_error = now;
                    }
                    continue;
                }
            };
            if !tcp {
                stamp = generations.stamp(owner.pid, packet.flow, false);
            }
            let own_process = owner.pid == std::process::id();
            let managed_xray =
                stats
                    .xray_bypass
                    .classify(owner.pid, packet.flow.destination, packet.protocol);
            let internal = own_process || managed_xray.is_some();
            let names = if internal {
                Vec::new()
            } else {
                domains.lock().unwrap().lookup(packet.flow.destination.ip())
            };
            let flow = Flow {
                process_name: &owner.name,
                process_path: &owner.path,
                destination: packet.flow.destination,
                protocol: packet.protocol,
                domains: &names,
            };
            let action = match managed_xray {
                Some((_, true)) => Action::Direct,
                Some((_, false)) => Action::Block,
                None if own_process => Action::Direct,
                None => rules::resolve(&config, &flow),
            };
            let needs_syn = tcp && matches!(action, Action::Proxy(_)) && !packet.is_syn();
            let observe = match &action {
                Action::Direct => true,
                Action::Block => stats.activity.tracking(),
                Action::Proxy(_) => tcp && !needs_syn,
            };
            let mut record = None;
            if !internal && (observe || stats.log_tracking()) {
                let route = match &action {
                    Action::Direct => "Direct".into(),
                    Action::Block => "Block".into(),
                    Action::Proxy(id) => config
                        .proxy(id)
                        .map(|p| p.name.clone())
                        .unwrap_or_else(|_| "Proxy not found".into()),
                };
                let explanation = rules::explanation(&config, &flow);
                stats.log(
                    LogSource::Connections,
                    LogLevel::Info,
                    &owner.name,
                    packet.flow.destination.to_string(),
                    &route,
                    &explanation,
                );
                if observe {
                    let info = Info {
                        pid: owner.pid,
                        process: owner.name.clone(),
                        source: packet.flow.source,
                        destination: packet.flow.destination,
                        protocol: packet.protocol,
                        route,
                        detail: explanation,
                        action: action.clone(),
                        stamp: address.timestamp(),
                    };
                    if action == Action::Block {
                        stats.activity.completed(info, Status::Blocked);
                    } else {
                        record = stats.activity.start(
                            info,
                            if action == Action::Direct && (!tcp || !packet.is_syn()) {
                                Status::Active
                            } else {
                                Status::Connecting
                            },
                        );
                    }
                }
            }
            if let Action::Proxy(id) = &action
                && tcp
            {
                // Do not take over a TCP connection established before interception began.
                if needs_syn {
                    stats.blocked.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let listener_port = if packet.flow.source.is_ipv4() {
                    port4
                } else {
                    port6
                };
                let mut table = nat.lock().unwrap();
                let mut reflected = None;
                for _ in 0..55000 {
                    synthetic = if synthetic >= 65000 {
                        10000
                    } else {
                        synthetic + 1
                    };
                    let candidate = FlowKey {
                        source: SocketAddr::new(packet.flow.source.ip(), listener_port),
                        destination: SocketAddr::new(packet.flow.destination.ip(), synthetic),
                    };
                    if !table.reflected.contains_key(&candidate) {
                        reflected = Some(candidate);
                        break;
                    }
                }
                if let Some(reflected) = reflected {
                    table.original.insert(packet.flow, reflected);
                    table.reflected.insert(
                        reflected,
                        Nat {
                            original: packet.flow,
                            proxy_id: id.clone(),
                            process: owner.name.clone(),
                            last: now,
                            active: Arc::new(AtomicBool::new(false)),
                            record: record.clone(),
                        },
                    );
                } else {
                    if let Some(c) = &record {
                        c.finish(Status::Failed, "TCP connection limit reached");
                    }
                    stats.blocked.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
            decisions.insert(
                key,
                Decision {
                    action: action.clone(),
                    xray_generation: managed_xray.map(|(generation, _)| generation),
                    last: now,
                    stamp,
                    initial_sequence: packet.tcp_sequence,
                    owner,
                    dns_check: now,
                    record,
                },
            );
            action
        };
        if let Some(d) = decisions.get_mut(&key) {
            if d.record
                .as_ref()
                .is_some_and(|record| record.status() == Status::Stopped)
            {
                d.record = None;
            }
            if !tcp
                && action == Action::Direct
                && let Some(old) = &d.record
                && old.status().finished()
            {
                let mut info = old.info();
                info.stamp = address.timestamp();
                d.record = stats.activity.start(info, Status::Active);
            }
            if let Some(record) = &d.record {
                if !tcp && action == Action::Direct {
                    record.touch();
                }
                if tcp && packet.tcp_flags & 4 != 0 {
                    record.finish(Status::Closed, "TCP RST");
                } else if tcp && packet.tcp_flags & 1 != 0 {
                    record.closing();
                } else if tcp && action == Action::Direct && !packet.is_syn() {
                    record.active();
                }
            }
        }
        match action {
            Action::Direct => device.send(bytes, &address)?,
            Action::Block => {
                stats.blocked.fetch_add(1, Ordering::Relaxed);
            }
            Action::Proxy(id) if tcp => {
                let reflected = {
                    let mut table = nat.lock().unwrap();
                    let key = table.original.get(&packet.flow).copied();
                    if let Some(key) = key
                        && let Some(n) = table.reflected.get_mut(&key)
                    {
                        n.last = now;
                    }
                    key
                };
                if let Some(reflected) = reflected {
                    packet.reflect_tcp(
                        bytes,
                        reflected.destination.port(),
                        reflected.source.port(),
                    );
                    device.reflect(bytes, &mut address)?;
                } else {
                    stats.blocked.fetch_add(1, Ordering::Relaxed);
                }
                let _ = id;
            }
            Action::Proxy(id) => {
                if let Some(decision) = decisions.get(&key) {
                    let _ = udp.send(
                        SocketId {
                            pid: decision.owner.pid,
                            local: packet.flow.source,
                            generation: decision.stamp,
                        },
                        Owner {
                            name: &decision.owner.name,
                            path: &decision.owner.path,
                        },
                        &id,
                        Outgoing {
                            destination: packet.flow.destination,
                            payload: packet.payload(bytes),
                            address,
                            stamp: address.timestamp(),
                        },
                    );
                }
            }
        }
    }
    Ok(())
}

async fn accept_loop(
    listener: TcpListener,
    nat: NatTable,
    config: Arc<Config>,
    stats: Arc<Statistics>,
) {
    while let Ok((stream, peer)) = listener.accept().await {
        let Ok(local) = stream.local_addr() else {
            continue;
        };
        let key = FlowKey {
            source: local,
            destination: peer,
        };
        let mapping = nat.lock().unwrap().reflected.get(&key).cloned();
        if let Some(mapping) = mapping {
            mapping.active.store(true, Ordering::Relaxed);
            let config = config.clone();
            let stats = stats.clone();
            tokio::spawn(async move {
                struct ActiveGuard(Arc<AtomicBool>);
                impl Drop for ActiveGuard {
                    fn drop(&mut self) {
                        self.0.store(false, Ordering::Relaxed);
                    }
                }
                let _active = ActiveGuard(mapping.active.clone());
                let result = tcp_session(stream, &mapping, &config, &stats).await;
                if let Err(error) = result {
                    stats.log(
                        LogSource::Connections,
                        LogLevel::Error,
                        mapping.process,
                        mapping.original.destination.to_string(),
                        "",
                        format!("TCP · {error:#}"),
                    );
                }
            });
        }
    }
}

async fn tcp_session(
    mut local: TcpStream,
    mapping: &Nat,
    config: &Config,
    stats: &Arc<Statistics>,
) -> Result<()> {
    let _session = mapping.record.as_ref().map(Connection::session);
    let result = async {
        local.set_nodelay(true)?;
        let mut remote = socks::connect(
            config.proxy(&mapping.proxy_id)?,
            mapping.original.destination,
        )
        .await?;
        if let Some(c) = &mapping.record {
            c.active();
        }
        let guard = stats.connection(&mapping.process);
        crate::transfer::relay_for_process(
            &mut local,
            &mut remote,
            &stats.uploaded,
            &stats.downloaded,
            &guard.process.uploaded,
            &guard.process.downloaded,
        )
        .await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(error) = &result
        && let Some(c) = &mapping.record
    {
        c.finish(Status::Failed, &format!("{error:#}"));
    }
    result
}
