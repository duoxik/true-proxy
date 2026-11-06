//! Invalidate cached routing when a local socket is closed or its port is reused.
use super::divert::{Device, SocketClose};
use crate::{
    engine::{FailureHandler, Statistics},
    packet::FlowKey,
};
use anyhow::Result;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

#[derive(Default)]
struct Generations {
    epoch: u64,
    ports: HashMap<(u32, IpAddr, u16, bool), Closed>,
}

#[derive(Default)]
struct Closed {
    generation: u64,
    stamp: i64,
}

pub struct SocketMonitor {
    device: Arc<Device>,
    thread: Option<thread::JoinHandle<()>>,
    stopping: Arc<AtomicBool>,
    generations: Arc<Mutex<Generations>>,
}

#[derive(Clone, Default)]
pub struct SocketGenerations(Arc<Mutex<Generations>>);

impl SocketGenerations {
    fn wildcard(flow: FlowKey) -> IpAddr {
        if flow.source.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        }
    }
    fn read_stamp(g: &Generations, pid: u32, flow: FlowKey, tcp: bool) -> (u64, u64, u64) {
        let exact = g
            .ports
            .get(&(pid, flow.source.ip(), flow.source.port(), tcp));
        let wildcard = g
            .ports
            .get(&(pid, Self::wildcard(flow), flow.source.port(), tcp));
        (
            g.epoch,
            exact.map_or(0, |e| e.generation),
            wildcard.map_or(0, |e| e.generation),
        )
    }
    pub fn stamp(&self, pid: u32, flow: FlowKey, tcp: bool) -> (u64, u64, u64) {
        Self::read_stamp(&self.0.lock().unwrap(), pid, flow, tcp)
    }
    /// The immutable birth of an association, not the latest packet on the port,
    /// decides which CLOSE applies. Both WinDivert layers use QPC timestamps.
    pub fn valid(&self, pid: u32, flow: FlowKey, birth: i64, generation: (u64, u64, u64)) -> bool {
        let g = self.0.lock().unwrap();
        if g.epoch != generation.0 {
            return false;
        }
        if birth <= 0 {
            return Self::read_stamp(&g, pid, flow, false) == generation;
        }
        [
            (flow.source.ip(), generation.1),
            (Self::wildcard(flow), generation.2),
        ]
        .into_iter()
        .all(|(ip, previous)| {
            g.ports
                .get(&(pid, ip, flow.source.port(), false))
                .is_none_or(|closed| {
                    if closed.stamp > 0 {
                        birth > closed.stamp
                    } else {
                        closed.generation == previous
                    }
                })
        })
    }
    pub fn closed(&self, event: &SocketClose) {
        if event.tcp || event.source.port() == 0 {
            return;
        }
        let mut g = self.0.lock().unwrap();
        if g.ports.len() >= 8192 {
            g.ports.clear();
            g.epoch = g.epoch.wrapping_add(1);
        }
        // Never ignore a delayed CLOSE. An old live relay must still be invalidated.
        let closed = g
            .ports
            .entry((event.pid, event.source.ip(), event.source.port(), false))
            .or_default();
        closed.generation = closed.generation.wrapping_add(1);
        closed.stamp = closed.stamp.max(event.stamp);
    }
}

impl SocketMonitor {
    pub fn start(
        device: Arc<Device>,
        failure: FailureHandler,
        stats: Arc<Statistics>,
    ) -> Result<Self> {
        let generations = Arc::new(Mutex::new(Generations::default()));
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_device = device.clone();
        let worker_generations = SocketGenerations(generations.clone());
        let worker_stopping = stopping.clone();
        let thread = thread::Builder::new()
            .name("socket-monitor".into())
            .spawn(move || {
                loop {
                    match worker_device.recv_socket_change() {
                        Ok(event) => {
                            if event.source.port() == 0 {
                                continue;
                            }
                            worker_generations.closed(&event);
                            stats.activity.close_socket(
                                event.pid,
                                event.source,
                                event.destination,
                                event.tcp,
                                event.stamp,
                            );
                        }
                        Err(error) => {
                            if !worker_stopping.load(Ordering::Acquire) {
                                failure(format!("Socket owner tracking stopped: {error:#}"));
                            }
                            break;
                        }
                    }
                }
            })?;
        Ok(Self {
            device,
            thread: Some(thread),
            stopping,
            generations,
        })
    }
    pub fn generations(&self) -> SocketGenerations {
        SocketGenerations(self.generations.clone())
    }
}
impl Drop for SocketMonitor {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        self.device.shutdown();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn close_boundaries_are_pid_scoped_and_preserve_only_newer_births() {
        for (local, remote, closed_source) in [
            ("192.0.2.1:3097", "203.0.113.7:3478", "0.0.0.0:3097"),
            ("192.0.2.1:3097", "203.0.113.7:3478", "192.0.2.1:3097"),
            ("[2001:db8::1]:3097", "[2001:db8::7]:3478", "[::]:3097"),
            (
                "[2001:db8::1]:3097",
                "[2001:db8::7]:3478",
                "[2001:db8::1]:3097",
            ),
        ] {
            let g = SocketGenerations::default();
            let flow = FlowKey {
                source: local.parse().unwrap(),
                destination: remote.parse().unwrap(),
            };
            let first = g.stamp(10, flow, false);
            let mut close = SocketClose {
                pid: 9,
                source: closed_source.parse().unwrap(),
                destination: remote.parse().unwrap(),
                tcp: false,
                stamp: 150,
            };
            g.closed(&close);
            assert!(g.valid(10, flow, 100, first), "other PID's CLOSE");
            close.pid = 10;
            g.closed(&close);
            assert!(
                !g.valid(10, flow, 100, first),
                "old association must die even after a newer packet"
            );
            assert!(
                g.valid(10, flow, 200, first),
                "a truly new association survives old CLOSE"
            );
            close.stamp = 300;
            g.closed(&close);
            assert!(!g.valid(10, flow, 200, first), "current CLOSE");
            close.stamp = 120;
            g.closed(&close);
            assert!(
                !g.valid(10, flow, 200, first),
                "out-of-order CLOSE cannot lower the boundary"
            );
        }
    }
}
