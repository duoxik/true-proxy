use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::windows::process::CommandExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};
use true_proxy::{
    config::{Action, Config, DnsPolicy, Protocol, Proxy, Rule},
    dns,
    packet::FlowKey,
    platform::windows::process,
    rules::{self, Flow},
    socks, transfer,
};

const FAKE_IP: Ipv4Addr = Ipv4Addr::new(127, 77, 54, 1);
const DNS_IP: Ipv4Addr = Ipv4Addr::new(127, 77, 53, 1);
const TIMEOUT: Duration = Duration::from_secs(12);

// This owns the Child handle returned by spawn; cleanup never finds/kills by name.
struct Helper(Option<Child>);
impl Drop for Helper {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
impl Helper {
    fn pid(&self) -> u32 {
        self.0.as_ref().unwrap().id()
    }
    fn result(mut self) -> Result<Value> {
        let output = self.0.take().unwrap().wait_with_output()?;
        ensure!(
            output.status.success(),
            "Owned helper failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(serde_json::from_slice(&output.stdout)?)
    }
}

fn query(name: &str) -> Vec<u8> {
    let mut bytes = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.extend_from_slice(&[0, 0, 1, 0, 1]);
    bytes
}

/// Minimal A/AAAA responder for the one controlled .invalid name in this probe.
/// Other RR types are REFUSED: the probe must not pretend Fake-IP covers them.
fn answer(query: &[u8], name: &str, ip: Ipv4Addr) -> Result<Vec<u8>> {
    ensure!(dns::questions(query)? == [name], "Unexpected test DNS name");
    let mut end = 12;
    while *query.get(end).context("Truncated test name")? != 0 {
        end += query[end] as usize + 1;
    }
    end += 5;
    ensure!(end <= query.len(), "Truncated test question");
    let kind = u16::from_be_bytes([query[end - 4], query[end - 3]]);
    let mut bytes = query[..end].to_vec();
    bytes[2] = 0x81;
    bytes[3] = if matches!(kind, 1 | 28) { 0x80 } else { 0x85 };
    bytes[6..12].fill(0);
    if kind == 1 {
        bytes[7] = 1;
        bytes.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4]); // TTL 300
        bytes.extend_from_slice(&ip.octets());
    }
    Ok(bytes)
}

async fn mock_socks(
    label: &'static str,
    ip: Ipv4Addr,
    name: String,
    listener: TcpListener,
    count: Arc<AtomicU64>,
) -> Result<()> {
    // One DNS exchange and one payload stream. The mock never opens an upstream socket.
    for _ in 0..2 {
        let (mut stream, _) = timeout(TIMEOUT, listener.accept()).await??;
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await?;
        ensure!(greeting == [5, 1, 0], "Wrong SOCKS greeting");
        stream.write_all(&[5, 0]).await?;
        let mut request = [0; 10];
        stream.read_exact(&mut request).await?;
        ensure!(request[..4] == [5, 1, 0, 1], "Expected IPv4 CONNECT");
        let target = Ipv4Addr::new(request[4], request[5], request[6], request[7]);
        let port = u16::from_be_bytes([request[8], request[9]]);
        stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        if port == 53 {
            ensure!(
                target == Ipv4Addr::new(192, 0, 2, 53),
                "Wrong mock resolver target"
            );
            let size = stream.read_u16().await? as usize;
            let mut request = vec![0; size];
            stream.read_exact(&mut request).await?;
            let response = answer(&request, &name, ip)?;
            count.fetch_add(1, Ordering::Relaxed);
            stream.write_u16(response.len() as u16).await?;
            stream.write_all(&response).await?;
        } else {
            ensure!(target == ip, "Payload used the wrong route's DNS response");
            let mut body = Vec::new();
            stream.read_to_end(&mut body).await?;
            stream.write_all(format!("via-{label}:").as_bytes()).await?;
            stream.write_all(&body).await?;
        }
        stream.shutdown().await?;
    }
    Ok(())
}

fn proxy(id: &str, address: SocketAddr) -> Proxy {
    Proxy {
        id: id.into(),
        name: id.into(),
        host: address.ip().to_string(),
        port: address.port(),
        username: String::new(),
        protected_password: None,
    }
}
fn rule(name: &str, proxy_id: &str) -> Rule {
    Rule {
        id: name.into(),
        name: name.into(),
        enabled: true,
        process_names: vec![name.into()],
        process_paths: vec![],
        domains: vec![],
        domain_suffixes: vec![],
        networks: vec![],
        ports: vec![],
        protocol: Protocol::Both,
        action: Action::Proxy(proxy_id.into()),
        dns: DnsPolicy::Proxy,
    }
}

pub async fn run() -> Result<()> {
    let start = Instant::now();
    let args = std::env::args_os().collect::<Vec<_>>();
    ensure!(
        args.len() == 3,
        "Expected: path-to-dns-route-client.exe output-directory"
    );
    let client = PathBuf::from(&args[1]).canonicalize()?;
    let root = PathBuf::from(&args[2]);
    std::fs::create_dir_all(&root)?;
    let root = root.canonicalize()?;
    let run_id = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let directory = root.join(format!("run-{}-{run_id}", std::process::id()));
    std::fs::create_dir(&directory)?;
    let name = format!("tp-route-{run_id}.invalid");
    let server = UdpSocket::bind((DNS_IP, 53))
        .await
        .context("The probe's private loopback DNS address is already in use")?;
    let listener = TcpListener::bind((FAKE_IP, 0)).await?;
    let destination = listener.local_addr()?;
    let fake_queries = Arc::new(AtomicU64::new(0));
    let fake_count = fake_queries.clone();
    let fake_name = name.clone();
    let fake_server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        loop {
            let (length, peer) = server.recv_from(&mut buffer).await?;
            ensure!(peer.ip().is_loopback(), "Unexpected external peer");
            let reply = answer(&buffer[..length], &fake_name, FAKE_IP)?;
            fake_count.fetch_add(1, Ordering::Relaxed);
            server.send_to(&reply, peer).await?;
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    });
    let first = TcpListener::bind("127.0.0.1:0").await?;
    let second = TcpListener::bind("127.0.0.1:0").await?;
    let count_a = Arc::new(AtomicU64::new(0));
    let count_b = Arc::new(AtomicU64::new(0));
    let mut config = Config::default();
    config.dns.enabled = false;
    config.proxies = vec![
        proxy("socks-a", first.local_addr()?),
        proxy("socks-b", second.local_addr()?),
    ];
    config.rules = vec![
        rule("dns-probe-a.exe", "socks-a"),
        rule("dns-probe-b.exe", "socks-b"),
    ];
    config.validate()?;
    let first_server = tokio::spawn(mock_socks(
        "A",
        Ipv4Addr::new(192, 0, 2, 11),
        name.clone(),
        first,
        count_a.clone(),
    ));
    let second_server = tokio::spawn(mock_socks(
        "B",
        Ipv4Addr::new(192, 0, 2, 22),
        name.clone(),
        second,
        count_b.clone(),
    ));
    let config = Arc::new(config);
    let mut helpers = Vec::new();
    let mut expected = std::collections::HashMap::new();
    for (executable, payload, route) in [
        ("dns-probe-a.exe", "client-a", "socks-a"),
        ("dns-probe-b.exe", "client-b", "socks-b"),
    ] {
        let path = directory.join(executable);
        std::fs::copy(&client, &path)?;
        let child = Command::new(path)
            .args([
                DNS_IP.to_string(),
                name.clone(),
                destination.port().to_string(),
                payload.into(),
            ])
            .creation_flags(0x08000000)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let child = Helper(Some(child));
        expected.insert(child.pid(), route.to_string());
        helpers.push(child);
    }
    let mut forwards = Vec::new();
    for index in 0..2 {
        let (mut stream, peer) = timeout(TIMEOUT, listener.accept()).await??;
        if index == 0 {
            ensure!(
                count_a.load(Ordering::Relaxed) + count_b.load(Ordering::Relaxed) == 0,
                "DNS escaped before process attribution"
            );
        }
        let owner = process::identify(
            FlowKey {
                source: peer,
                destination,
            },
            Protocol::Tcp,
        )?;
        let action = rules::resolve(
            &config,
            &Flow {
                process_name: &owner.name,
                process_path: &owner.path,
                destination,
                protocol: Protocol::Tcp,
                domains: std::slice::from_ref(&name),
            },
        );
        let Action::Proxy(id) = action else {
            bail!("The real helper process did not match its rule");
        };
        ensure!(
            expected.get(&owner.pid) == Some(&id),
            "IP Helper attributed the wrong process or rule"
        );
        let proxy = config.proxy(&id)?.clone();
        let name = name.clone();
        forwards.push(tokio::spawn(async move {
            let response = dns::exchange(&proxy, "192.0.2.53".parse()?, &query(&name)).await?;
            let resolved = dns::answers(&response)?.into_iter().next().context("No mock A answer")?.0;
            ensure!(matches!(resolved, IpAddr::V4(ip) if ip.octets()[..3] == [192,0,2]), "Unexpected non-test address");
            let mut remote = socks::connect(&proxy, SocketAddr::new(resolved, destination.port())).await?;
            let upload = AtomicU64::new(0); let download = AtomicU64::new(0);
            transfer::relay(&mut stream, &mut remote, &upload, &download).await?;
            Ok::<_, anyhow::Error>(json!({"pid": owner.pid, "process": owner.name, "proxy": id, "dns_answer": resolved, "uploaded": upload.load(Ordering::Relaxed), "downloaded": download.load(Ordering::Relaxed)}))
        }));
    }
    let mut routes = Vec::new();
    for forward in forwards {
        routes.push(timeout(TIMEOUT, forward).await???);
    }
    let mut results = Vec::new();
    for helper in helpers {
        results.push(tokio::task::spawn_blocking(move || helper.result()).await??);
    }
    for (label, expected_reply) in [("socks-a", "via-A:client-a"), ("socks-b", "via-B:client-b")] {
        let route = routes
            .iter()
            .find(|route| route["proxy"] == label)
            .context("Missing route")?;
        let result = results
            .iter()
            .find(|result| result["pid"] == route["pid"])
            .context("Missing helper result")?;
        ensure!(
            result["reply"] == expected_reply && result["fake_ip"] == FAKE_IP.to_string(),
            "Wrong stream route or fake IP"
        );
    }
    first_server.await??;
    second_server.await??;
    fake_server.abort();
    ensure!(
        count_a.load(Ordering::Relaxed) == 1 && count_b.load(Ordering::Relaxed) == 1,
        "Wrong per-proxy DNS counts"
    );
    let report = json!({
        "ok": true, "scope": "Owned helpers, ordinary Windows resolver, loopback DNS/SOCKS mocks. No WinDivert, foreign process changes, or game compatibility test.",
        "domain": name, "shared_fake_ip": FAKE_IP, "routes": routes, "clients": results,
        "dns_queries_by_proxy": {"socks-a": count_a.load(Ordering::Relaxed), "socks-b": count_b.load(Ordering::Relaxed)},
        "fake_dns_queries": fake_queries.load(Ordering::Relaxed), "elapsed_ms": start.elapsed().as_millis(),
        "not_covered": ["system-wide DNS interception", "unselected/direct applications", "UDP payload relay", "IPv6", "SRV/TXT and DNSSEC", "DNS-only queries without a connection", "deferred-mode proxy failure", "cache/restart persistence", "games/anti-cheat", "real VPN"]
    });
    std::fs::write(
        directory.join("result.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    std::fs::write(
        root.join("latest-result.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
