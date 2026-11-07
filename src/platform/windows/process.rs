//! IP Helper snapshots for routing ownership and passive TCP observation.
use crate::{config::Protocol, connections::Status, packet::FlowKey};
use anyhow::{Result, bail, ensure};
use std::{
    collections::{HashMap, HashSet},
    ffi::c_void,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    ptr,
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    },
    System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    },
};

#[link(name = "iphlpapi")]
unsafe extern "system" {
    fn GetExtendedTcpTable(
        table: *mut c_void,
        size: *mut u32,
        order: i32,
        family: u32,
        class: u32,
        reserved: u32,
    ) -> u32;
    fn GetExtendedUdpTable(
        table: *mut c_void,
        size: *mut u32,
        order: i32,
        family: u32,
        class: u32,
        reserved: u32,
    ) -> u32;
}

#[derive(Clone, Default)]
pub struct Process {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

/// One batch owner lookup for idle routing-cache entries. This is core socket
/// lifetime data, independent of whether the connection journal is observed.
/// Keep only requested tuples so the returned map remains bounded by the cache.
pub fn tcp_snapshot(candidates: &HashSet<FlowKey>) -> Result<HashMap<FlowKey, u32>> {
    let mut owners = HashMap::new();
    for ipv4 in [true, false] {
        if !candidates.iter().any(|flow| flow.source.is_ipv4() == ipv4) {
            continue;
        }
        visit_live_tcp(ipv4, |flow, pid, _| {
            // Packet tuples do not contain IPv6 interface scope IDs.
            let flow = FlowKey {
                source: SocketAddr::new(flow.source.ip(), flow.source.port()),
                destination: SocketAddr::new(flow.destination.ip(), flow.destination.port()),
            };
            if candidates.contains(&flow)
                && let Some(previous) = owners.insert(flow, pid)
            {
                ensure!(previous == pid, "Conflicting TCP connection owners");
            }
            Ok(())
        })?;
    }
    Ok(owners)
}

pub(super) fn visit_live_tcp(
    ipv4: bool,
    mut visit: impl FnMut(FlowKey, u32, Status) -> Result<()>,
) -> Result<()> {
    let family = if ipv4 { 2 } else { 23 };
    let mut size = 0;
    let status = unsafe { GetExtendedTcpTable(ptr::null_mut(), &mut size, 0, family, 5, 0) };
    ensure!(
        status == 0 || status == 122,
        "Could not read the TCP table size ({status})"
    );
    for _ in 0..3 {
        ensure!(
            (4..=16 * 1024 * 1024).contains(&size),
            "Invalid TCP table size"
        );
        // u32 storage has the alignment required by both MIB owner tables.
        let mut words = vec![0u32; (size as usize).div_ceil(4)];
        let status =
            unsafe { GetExtendedTcpTable(words.as_mut_ptr().cast(), &mut size, 0, family, 5, 0) };
        if status == 122 {
            continue;
        }
        ensure!(status == 0, "Could not read the TCP table ({status})");
        ensure!(
            (4..=words.len() * 4).contains(&(size as usize)),
            "Invalid TCP table length"
        );
        // Windows wrote at most `size` bytes into the aligned buffer above.
        let bytes =
            unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), size as usize) };
        let count = words[0] as usize;
        let stride = if ipv4 { 24 } else { 56 };
        ensure!(count <= (bytes.len() - 4) / stride, "Truncated TCP table");
        for row in bytes[4..4 + count * stride].chunks_exact(stride) {
            let (local, local_port, remote, remote_port, state, pid) = if ipv4 {
                (4, 8, 12, 16, 0, 20)
            } else {
                (0, 20, 24, 44, 48, 52)
            };
            let state = match u32::from_ne_bytes(row[state..state + 4].try_into()?) {
                3 | 4 => Status::Connecting,
                5 => Status::Active,
                6..=10 => Status::Closing,
                _ => continue,
            };
            let endpoint = |addr, port| {
                let ip = read_ip(row, addr, ipv4);
                let port = u16::from_be_bytes([row[port], row[port + 1]]);
                if let IpAddr::V6(ip) = ip {
                    let scope = u32::from_be_bytes(row[addr + 16..addr + 20].try_into().unwrap());
                    SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope))
                } else {
                    SocketAddr::new(ip, port)
                }
            };
            let flow = FlowKey {
                source: endpoint(local, local_port),
                destination: endpoint(remote, remote_port),
            };
            let pid = u32::from_ne_bytes(row[pid..pid + 4].try_into()?);
            visit(flow, pid, state)?;
        }
        return Ok(());
    }
    bail!("The TCP table is changing too quickly")
}
/// One on-demand snapshot; no polling, memory access, or process injection.
pub fn running_processes() -> Result<Vec<crate::platform::RunningProcess>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    ensure!(
        snapshot != INVALID_HANDLE_VALUE,
        "Could not list running processes: {}",
        std::io::Error::last_os_error()
    );
    struct Snapshot(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for Snapshot {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
    let snapshot = Snapshot(snapshot);
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut available = unsafe { Process32FirstW(snapshot.0, &mut entry) } != 0;
    let mut grouped = std::collections::BTreeMap::<String, crate::platform::RunningProcess>::new();
    let mut scanned = 0;
    while available && grouped.len() < 2048 && scanned < 16384 {
        scanned += 1;
        if entry.th32ProcessID != 0 {
            let end = entry
                .szExeFile
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
            let path = image_path(entry.th32ProcessID).unwrap_or_default();
            let key = format!("{}|{}", name.to_lowercase(), path.to_lowercase());
            let row = grouped
                .entry(key)
                .or_insert_with(|| crate::platform::RunningProcess {
                    name,
                    path,
                    pids: vec![],
                });
            row.pids.push(entry.th32ProcessID);
        }
        available = unsafe { Process32NextW(snapshot.0, &mut entry) } != 0;
    }
    Ok(grouped.into_values().collect())
}

pub(super) fn image_path(pid: u32) -> Result<String> {
    // Query-only access; the owned handle is closed before any parsing can fail.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    ensure!(
        !handle.is_null(),
        "Could not read the executable path for PID {pid}"
    );
    let mut path = vec![0u16; 32768];
    let mut length = path.len() as u32;
    let result = unsafe { QueryFullProcessImageNameW(handle, 0, path.as_mut_ptr(), &mut length) };
    unsafe { CloseHandle(handle) };
    ensure!(
        result != 0,
        "Could not read the executable path for PID {pid}"
    );
    Ok(String::from_utf16(&path[..length as usize])?)
}

pub fn identify(flow: FlowKey, protocol: Protocol) -> Result<Process> {
    identify_pid(owner_pid(flow, protocol)?)
}

pub(super) fn identify_pid(pid: u32) -> Result<Process> {
    if pid == 4 {
        // Windows denies OpenProcess(System), including for kernel-owned SMB.
        // The owner table already supplied the PID: retain that known identity,
        // without inventing an executable path or bypassing the rule engine.
        return Ok(Process {
            pid,
            name: "System".into(),
            path: String::new(),
        });
    }
    if pid == std::process::id() {
        return Ok(Process {
            pid,
            ..Default::default()
        });
    }
    let path = image_path(pid)?;
    let name = path.rsplit(['\\', '/']).next().unwrap_or("").to_string();
    Ok(Process { pid, name, path })
}

fn owner_pid(flow: FlowKey, protocol: Protocol) -> Result<u32> {
    let tcp = protocol == Protocol::Tcp;
    let ipv4 = flow.source.is_ipv4();
    let family = if ipv4 { 2 } else { 23 };
    let call = if tcp {
        GetExtendedTcpTable
    } else {
        GetExtendedUdpTable
    };
    let class = if tcp { 5 } else { 1 };
    let mut size = 0;
    unsafe { call(ptr::null_mut(), &mut size, 0, family, class, 0) };
    ensure!(
        (4..=16 * 1024 * 1024).contains(&size),
        "Invalid connection table size"
    );
    // u32 storage provides the alignment expected by MIB_*TABLE structs.
    let mut words = vec![0u32; (size as usize).div_ceil(4)];
    let status = unsafe { call(words.as_mut_ptr().cast(), &mut size, 0, family, class, 0) };
    ensure!(
        status == 0,
        "Could not read the connection table ({status})"
    );
    let bytes = unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), size as usize) };
    let count = words[0] as usize;
    let stride = match (tcp, ipv4) {
        (true, true) => 24,
        (true, false) => 56,
        (false, true) => 12,
        (false, false) => 28,
    };
    ensure!(
        4 + count * stride <= bytes.len(),
        "Truncated connection table"
    );
    let mut found = None;
    for row in bytes[4..4 + count * stride].chunks_exact(stride) {
        let (addr_offset, port_offset, pid_offset) = match (tcp, ipv4) {
            (true, true) => (4, 8, 20),
            (true, false) => (0, 20, 52),
            (false, true) => (0, 4, 8),
            (false, false) => (0, 20, 24),
        };
        let local = read_ip(row, addr_offset, ipv4);
        let local_port = u16::from_be_bytes([row[port_offset], row[port_offset + 1]]);
        if local_port != flow.source.port()
            || (!local.is_unspecified() && local != flow.source.ip())
        {
            continue;
        }
        if tcp {
            let (remote_offset, remote_port_offset) = if ipv4 { (12, 16) } else { (24, 44) };
            if read_ip(row, remote_offset, ipv4) != flow.destination.ip()
                || u16::from_be_bytes([row[remote_port_offset], row[remote_port_offset + 1]])
                    != flow.destination.port()
            {
                continue;
            }
        }
        let pid = u32::from_ne_bytes(row[pid_offset..pid_offset + 4].try_into()?);
        if let Some(other) = found {
            ensure!(
                other == pid,
                "The UDP connection was blocked because multiple processes share its port"
            );
        }
        found = Some(pid);
    }
    match found {
        Some(pid) => Ok(pid),
        None => bail!("Could not identify the process that owns the connection"),
    }
}

fn read_ip(bytes: &[u8], at: usize, ipv4: bool) -> IpAddr {
    if ipv4 {
        IpAddr::V4(Ipv4Addr::new(
            bytes[at],
            bytes[at + 1],
            bytes[at + 2],
            bytes[at + 3],
        ))
    } else {
        IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&bytes[at..at + 16]).unwrap(),
        ))
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    #[test]
    fn on_demand_process_list_includes_this_executable_without_elevation() {
        let rows = running_processes().unwrap();
        let own = rows
            .iter()
            .find(|row| row.pids.contains(&std::process::id()))
            .expect("Current process missing");
        assert!(!own.name.is_empty());
        assert!(std::path::Path::new(&own.path).is_absolute());
        assert!(rows.len() <= 2048);
    }

    #[test]
    fn system_owner_is_identified_without_a_fabricated_executable_path() {
        let owner = identify_pid(4).unwrap();
        assert_eq!(owner.pid, 4);
        assert_eq!(owner.name, "System");
        assert!(owner.path.is_empty());
    }

    #[test]
    fn inaccessible_unknown_owner_is_still_an_error() {
        assert!(identify_pid(0).is_err());
        assert!(identify_pid(u32::MAX).is_err());
    }

    #[test]
    fn tcp_snapshot_returns_only_requested_live_tuples_and_their_real_pid() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let listener = std::net::TcpListener::bind(address).unwrap();
            let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _) = listener.accept().unwrap();
            let outgoing = FlowKey {
                source: client.local_addr().unwrap(),
                destination: client.peer_addr().unwrap(),
            };
            let incoming = FlowKey {
                source: server.local_addr().unwrap(),
                destination: server.peer_addr().unwrap(),
            };
            let missing = FlowKey {
                source: "192.0.2.254:1".parse().unwrap(),
                destination: "203.0.113.254:1".parse().unwrap(),
            };
            let owners = tcp_snapshot(&HashSet::from([outgoing, incoming, missing])).unwrap();
            assert_eq!(owners.len(), 2);
            assert_eq!(owners.get(&outgoing), Some(&std::process::id()));
            assert_eq!(owners.get(&incoming), Some(&std::process::id()));

            let mut connected = Vec::new();
            visit_live_tcp(outgoing.source.is_ipv4(), |flow, pid, status| {
                if flow == outgoing || flow == incoming {
                    assert_eq!(pid, std::process::id());
                    assert_eq!(status, Status::Active);
                    connected.push(flow);
                }
                Ok(())
            })
            .unwrap();
            assert!(connected.contains(&outgoing) && connected.contains(&incoming));
        }
    }

    #[test]
    fn system_traffic_obeys_direct_block_proxy_priority_and_default_rules() {
        use crate::{
            config::{Action, Config},
            rules::{self, Flow},
        };
        let owner = identify_pid(4).unwrap();
        let mut config: Config = serde_json::from_value(serde_json::json!({
            "version": 2, "routing_enabled": false,
            "proxies": [{"id": "vpn", "name": "VPN", "host": "127.0.0.1", "port": 1080}],
            "default_action": {"kind": "block"},
            "rules": [{
                "id": "nas", "name": "NAS", "enabled": true,
                "networks": ["203.0.113.1/32", "2001:db8::1/128"],
                "ports": [{"start": 445, "end": 445}], "action": {"kind": "direct"}
            }]
        }))
        .unwrap();
        config.validate().unwrap();
        for destination in ["203.0.113.1:445", "[2001:db8::1]:445"] {
            for protocol in [Protocol::Tcp, Protocol::Udp] {
                let flow = Flow {
                    process_name: &owner.name,
                    process_path: &owner.path,
                    destination: destination.parse().unwrap(),
                    protocol,
                    domains: &[],
                };
                assert_eq!(rules::resolve(&config, &flow), Action::Direct);
                // A known owner grants no direct bypass: the first matching rule wins.
                config.rules[0].process_names = vec!["System".into()];
                for action in [Action::Block, Action::Proxy("vpn".into()), Action::Direct] {
                    config.rules[0].action = action.clone();
                    assert_eq!(rules::resolve(&config, &flow), action);
                }
                let mut first = config.rules[0].clone();
                first.id = "block-first".into();
                first.action = Action::Block;
                config.rules.insert(0, first);
                assert_eq!(rules::resolve(&config, &flow), Action::Block);
                config.rules.remove(0);
                config.rules[0].enabled = false;
                assert_eq!(rules::resolve(&config, &flow), Action::Block);
                config.rules[0].enabled = true;
                // No full path is asserted for kernel-owned connections.
                config.rules[0].process_paths = vec![r"C:\Windows\System32\System.exe".into()];
                assert_eq!(rules::resolve(&config, &flow), Action::Block);
                config.rules[0].process_paths.clear();
                let mut other = flow;
                other.destination.set_port(446);
                assert_eq!(rules::resolve(&config, &other), Action::Block);
                for action in [Action::Direct, Action::Proxy("vpn".into()), Action::Block] {
                    config.default_action = action.clone();
                    assert_eq!(rules::resolve(&config, &other), action);
                }
            }
        }
    }

    #[test]
    fn system_owner_has_the_same_fixed_local_priority_as_other_processes() {
        use crate::{
            config::Config,
            rules::{self, Flow},
        };
        let owner = identify_pid(4).unwrap();
        let config = Config {
            default_action: crate::config::Action::Block,
            ..Config::default()
        };
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            for destination in ["192.168.50.1:445", "[fd00::1]:445"] {
                let flow = Flow {
                    process_name: &owner.name,
                    process_path: &owner.path,
                    destination: destination.parse().unwrap(),
                    protocol,
                    domains: &[],
                };
                assert_eq!(
                    rules::resolve(&config, &flow),
                    crate::config::Action::Direct
                );
            }
            let flow = Flow {
                process_name: &owner.name,
                process_path: &owner.path,
                destination: "203.0.113.1:445".parse().unwrap(),
                protocol,
                domains: &[],
            };
            assert_eq!(rules::resolve(&config, &flow), crate::config::Action::Block);
        }
    }
}
