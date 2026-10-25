use super::{
    divert::{Address, Device, Driver},
    monitor::{SocketGenerations, SocketMonitor},
    process,
};
use crate::{
    config::{Action, Config, Protocol},
    connections::{Connection, Info, Status},
    dns::{self, DomainCache},
    engine::{FailureHandler, Statistics},
    packet::{FlowKey, Packet, udp_reply},
    rules::{self, Flow},
    socks,
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    runtime::Runtime,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    time::timeout,
};

const MAX_FLOWS: usize = 4096;
const MAX_UDP_FLOWS: usize = 512;
const UDP_IDLE: Duration = Duration::from_secs(90);
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
    fn idle_direct_tcp_keeps_one_decision_until_closed_with_a_tail_packet_grace_period() {
        let stats = Arc::new(Statistics::default());
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
                    proxied: false,
                    stamp: 0,
                },
                Status::Active,
            )
            .unwrap();
        let now = Instant::now();
        let decision = Decision {
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
        assert!(decision.keep(
            flow,
            true,
            &NatMaps::default(),
            now + Duration::from_secs(3600)
        ));
        record.finish(Status::Closed, "");
        assert!(!decision.keep(
            flow,
            true,
            &NatMaps::default(),
            now + Duration::from_secs(3600)
        ));
        assert!(decision.keep(
            flow,
            true,
            &NatMaps::default(),
            now + Duration::from_secs(10)
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
            stats.activity.set_only_active(false);
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
                        proxied: true,
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
    last: Instant,
    stamp: (u64, u64, u64),
    initial_sequence: u32,
    owner: process::Process,
    dns_check: Instant,
    record: Option<Connection>,
}
impl Decision {
    fn keep(&self, flow: FlowKey, tcp: bool, table: &NatMaps, now: Instant) -> bool {
        now.duration_since(self.last) < Duration::from_secs(900)
            || (tcp && self.record.as_ref().is_some_and(|c| !c.status().finished()))
            || (tcp
                && table
                    .original
                    .get(&flow)
                    .and_then(|key| table.reflected.get(key))
                    .is_some_and(|n| n.active.load(Ordering::Relaxed)))
    }
}
struct Datagram {
    payload: Vec<u8>,
    address: Address,
    _memory: OwnedSemaphorePermit,
}
struct UdpFlow {
    sender: mpsc::Sender<Datagram>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for UdpFlow {
    fn drop(&mut self) {
        self.task.abort();
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
                    .context("Таймаут разрешения адреса прокси")??
                    .next()
                    .context("Не найден IP-адрес прокси")?;
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
                    worker_stats.log("Система", "", "Ошибка", format!("{error:#}"));
                    failure(format!("Перехват остановился: {error:#}"));
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
    let mut udp: HashMap<FlowKey, UdpFlow> = HashMap::new();
    let mut dns_flows = HashMap::<(FlowKey, bool), Instant>::new();
    let mut tcp_dns = HashMap::<FlowKey, dns::TcpDnsBuffer>::new();
    let has_domain_rules = config
        .rules
        .iter()
        .any(|rule| rule.enabled && (!rule.domains.is_empty() || !rule.domain_suffixes.is_empty()));
    let mut synthetic = 10000u16;
    let mut cleanup = Instant::now();
    let mut last_lookup_error = Instant::now() - Duration::from_secs(10);
    let queue_memory = Arc::new(Semaphore::new(4 * 1024 * 1024));
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
            let mut table = nat.lock().unwrap();
            table.cleanup(now);
            decisions.retain(|(flow, tcp), decision| decision.keep(*flow, *tcp, &table, now));
            drop(table);
            udp.retain(|_, flow| !flow.sender.is_closed());
            dns_flows.retain(|_, last| now.duration_since(*last) < Duration::from_secs(120));
            tcp_dns.retain(|flow, _| dns_flows.contains_key(&(*flow, true)));
            cleanup = now;
        }
        let tcp = packet.protocol == Protocol::Tcp;
        let key = (packet.flow, tcp);
        let stamp = if tcp {
            (0, 0, 0)
        } else {
            generations.stamp(packet.flow, false)
        };
        if decisions.get(&key).is_some_and(|d| {
            d.stamp != stamp
                || (tcp && packet.is_syn() && d.initial_sequence != packet.tcp_sequence)
        }) {
            if let Some(d) = decisions.remove(&key)
                && let Some(record) = d.record
            {
                record.finish(Status::Closed, "Новый экземпляр соединения");
            }
            udp.remove(&packet.flow);
            let mut table = nat.lock().unwrap();
            if let Some(reflected) = table.original.remove(&packet.flow) {
                table.reflected.remove(&reflected);
            }
        }
        let action = if let Some(d) = decisions.get_mut(&key) {
            d.last = now;
            if !tcp
                && has_domain_rules
                && d.action == Action::Direct
                && d.owner.pid != std::process::id()
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
                    udp.remove(&packet.flow);
                    let route = match &action {
                        Action::Direct => "Напрямую".into(),
                        Action::Block => "Блокировка".into(),
                        Action::Proxy(id) => config
                            .proxy(id)
                            .map(|proxy| proxy.name.clone())
                            .unwrap_or_else(|_| "Прокси отсутствует".into()),
                    };
                    stats.log(
                        &d.owner.name,
                        packet.flow.destination.to_string(),
                        route.clone(),
                        format!("UDP · маршрут уточнён по DNS: {}", names.join(", ")),
                    );
                    if let Some(old) = d.record.take() {
                        let mut info = old.info();
                        old.finish(Status::Closed, "Маршрут изменён");
                        info.route = route;
                        info.detail = format!("UDP · маршрут уточнён по DNS: {}", names.join(", "));
                        info.proxied = matches!(action, Action::Proxy(_));
                        info.stamp = address.timestamp();
                        if action == Action::Block {
                            stats.activity.completed(info, Status::Blocked);
                        } else {
                            d.record = stats.activity.start(
                                info,
                                if action == Action::Direct {
                                    Status::Active
                                } else {
                                    Status::Connecting
                                },
                            );
                        }
                    }
                    d.action = action;
                }
            }
            d.action.clone()
        } else {
            if decisions.len() >= MAX_FLOWS {
                stats.blocked.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let owner = (0..3).find_map(|attempt| {
                let result = process::identify(packet.flow, packet.protocol).ok();
                if result.is_none() && attempt < 2 {
                    thread::sleep(Duration::from_millis(1));
                }
                result
            });
            let Some(owner) = owner else {
                stats.blocked.fetch_add(1, Ordering::Relaxed);
                if last_lookup_error.elapsed() > Duration::from_secs(5) {
                    stats.log(
                        "Неизвестный процесс",
                        packet.flow.destination.to_string(),
                        "Блокировка",
                        "Не удалось надежно определить владельца соединения",
                    );
                    last_lookup_error = now;
                }
                continue;
            };
            let action = if owner.pid == std::process::id() {
                Action::Direct
            } else {
                let names = domains.lock().unwrap().lookup(packet.flow.destination.ip());
                rules::resolve(
                    &config,
                    &Flow {
                        process_name: &owner.name,
                        process_path: &owner.path,
                        destination: packet.flow.destination,
                        protocol: packet.protocol,
                        domains: &names,
                    },
                )
            };
            let mut record = None;
            if owner.pid != std::process::id() {
                let route = match &action {
                    Action::Direct => "Напрямую".into(),
                    Action::Block => "Блокировка".into(),
                    Action::Proxy(id) => config
                        .proxy(id)
                        .map(|p| p.name.clone())
                        .unwrap_or_else(|_| "Прокси отсутствует".into()),
                };
                let names = domains.lock().unwrap().lookup(packet.flow.destination.ip());
                let explanation = rules::explanation(
                    &config,
                    &Flow {
                        process_name: &owner.name,
                        process_path: &owner.path,
                        destination: packet.flow.destination,
                        protocol: packet.protocol,
                        domains: &names,
                    },
                );
                stats.log(
                    &owner.name,
                    packet.flow.destination.to_string(),
                    route.clone(),
                    explanation.clone(),
                );
                let info = Info {
                    pid: owner.pid,
                    process: owner.name.clone(),
                    source: packet.flow.source,
                    destination: packet.flow.destination,
                    protocol: packet.protocol,
                    route,
                    detail: explanation,
                    proxied: matches!(action, Action::Proxy(_)),
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
            if let Action::Proxy(id) = &action
                && tcp
            {
                // Do not take over a TCP connection established before interception began.
                if !packet.is_syn() {
                    if let Some(c) = &record {
                        c.finish(Status::Blocked, "Требуется новое TCP-соединение");
                    }
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
                        c.finish(Status::Failed, "Лимит TCP-соединений");
                    }
                    stats.blocked.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
            decisions.insert(
                key,
                Decision {
                    action: action.clone(),
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
                if udp.get(&packet.flow).is_some_and(|s| s.sender.is_closed()) {
                    udp.remove(&packet.flow);
                }
                if !udp.contains_key(&packet.flow) {
                    if udp.len() >= MAX_UDP_FLOWS {
                        if let Some(c) = decisions.get(&key).and_then(|d| d.record.as_ref()) {
                            c.finish(Status::Failed, "Лимит UDP-сессий");
                        }
                        stats.blocked.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let record = decisions.get_mut(&key).and_then(|decision| {
                        if let Some(old) = &decision.record
                            && old.status().finished()
                        {
                            let mut info = old.info();
                            info.stamp = address.timestamp();
                            decision.record = stats.activity.start(info, Status::Connecting);
                        }
                        decision.record.clone()
                    });
                    let (tx, rx) = mpsc::channel(16);
                    let task = runtime.spawn(udp_session(
                        packet.flow,
                        id,
                        rx,
                        UdpSessionContext {
                            config: config.clone(),
                            device: device.clone(),
                            stats: stats.clone(),
                            process: decisions
                                .get(&key)
                                .map(|decision| decision.owner.name.clone())
                                .unwrap_or_else(|| "Неизвестный процесс".into()),
                            record,
                        },
                    ));
                    udp.insert(packet.flow, UdpFlow { sender: tx, task });
                }
                if let Some(sender) = udp.get(&packet.flow) {
                    let Ok(memory) = queue_memory
                        .clone()
                        .try_acquire_many_owned(packet.payload(bytes).len() as u32)
                    else {
                        stats.blocked.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    if sender
                        .sender
                        .try_send(Datagram {
                            payload: packet.payload(bytes).to_vec(),
                            address,
                            _memory: memory,
                        })
                        .is_err()
                    {
                        stats.blocked.fetch_add(1, Ordering::Relaxed);
                    }
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
                        mapping.process,
                        mapping.original.destination.to_string(),
                        "Ошибка",
                        format!("{error:#}"),
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

struct UdpSessionContext {
    config: Arc<Config>,
    device: Arc<Device>,
    stats: Arc<Statistics>,
    process: String,
    record: Option<Connection>,
}
async fn udp_session(
    flow: FlowKey,
    id: String,
    mut rx: mpsc::Receiver<Datagram>,
    context: UdpSessionContext,
) {
    let UdpSessionContext {
        config,
        device,
        stats,
        process,
        record,
    } = context;
    let _session = record.as_ref().map(Connection::session);
    let result = async {
        let association = socks::associate(config.proxy(&id)?).await?;
        if let Some(c)=&record {c.active();}
        let guard = stats.connection(&process);
        let mut reply_buffer = vec![0; 65535];
        let mut control = association.control;
        let mut control_buffer = [0; 1];
        let mut last_address = None;
        loop { tokio::select! {
            query = timeout(UDP_IDLE, rx.recv()) => {
                let Ok(Some(query)) = query else { break; };
                let mut packet = vec![0, 0, 0];
                socks::encode_address(flow.destination, &mut packet);
                packet.extend_from_slice(&query.payload);
                association.socket.send(&packet).await?;
                stats.uploaded.fetch_add(query.payload.len() as u64, Ordering::Relaxed);
                guard.process.uploaded.fetch_add(query.payload.len() as u64, Ordering::Relaxed);
                last_address = Some(query.address);
            },
            reply = association.socket.recv(&mut reply_buffer) => {
                let len = reply?;
                let (source, payload) = socks::udp_payload(&reply_buffer[..len])?;
                ensure!(source == flow.destination, "UDP relay вернул ответ от неожиданного узла");
                if let Some(address) = last_address {
                    device.inject(udp_reply(flow, payload)?, address)?;
                    stats.downloaded.fetch_add(payload.len() as u64, Ordering::Relaxed);
                    guard.process.downloaded.fetch_add(payload.len() as u64, Ordering::Relaxed);
                }
            },
            _ = control.read(&mut control_buffer) => { anyhow::bail!("SOCKS5-сервер закрыл UDP ASSOCIATE"); }
        }}
        Ok::<_, anyhow::Error>(())
    }.await;
    if let Err(error) = result {
        if let Some(c) = &record {
            c.finish(Status::Failed, &format!("{error:#}"));
        }
        stats.log(
            process,
            flow.destination.to_string(),
            "Ошибка",
            format!("{error:#}"),
        );
        stats.blocked.fetch_add(1, Ordering::Relaxed);
    }
}
