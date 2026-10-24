//! Invalidate cached routing when a local socket is closed or its port is reused.
use super::divert::Device;
use crate::{engine::FailureHandler, packet::FlowKey};
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
    ports: HashMap<(IpAddr, u16, bool), u64>,
}

pub struct SocketMonitor {
    device: Arc<Device>,
    thread: Option<thread::JoinHandle<()>>,
    stopping: Arc<AtomicBool>,
    generations: Arc<Mutex<Generations>>,
}

#[derive(Clone)]
pub struct SocketGenerations(Arc<Mutex<Generations>>);

impl SocketGenerations {
    pub fn stamp(&self, flow: FlowKey, tcp: bool) -> (u64, u64, u64) {
        let g = self.0.lock().unwrap();
        let wildcard = if flow.source.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        (
            g.epoch,
            *g.ports
                .get(&(flow.source.ip(), flow.source.port(), tcp))
                .unwrap_or(&0),
            *g.ports
                .get(&(wildcard, flow.source.port(), tcp))
                .unwrap_or(&0),
        )
    }
}

impl SocketMonitor {
    pub fn start(device: Arc<Device>, failure: FailureHandler) -> Result<Self> {
        let generations = Arc::new(Mutex::new(Generations::default()));
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_device = device.clone();
        let worker_generations = generations.clone();
        let worker_stopping = stopping.clone();
        let thread=thread::Builder::new().name("socket-monitor".into()).spawn(move||{
            loop {match worker_device.recv_socket_change() {
                Ok((ip,port,tcp))=>{if port==0{continue;}let mut g=worker_generations.lock().unwrap();if g.ports.len()>=8192{g.ports.clear();g.epoch=g.epoch.wrapping_add(1);}let generation=g.ports.entry((ip,port,tcp)).or_default();*generation=generation.wrapping_add(1);},
                Err(error)=>{if !worker_stopping.load(Ordering::Acquire){failure(format!("Не удалось продолжить отслеживание владельцев сокетов: {error:#}"));}break;}
            }}
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
    fn port_reuse_changes_routing_generation() {
        let g = SocketGenerations(Arc::default());
        let f = FlowKey {
            source: "192.0.2.1:5000".parse().unwrap(),
            destination: "203.0.113.1:443".parse().unwrap(),
        };
        let first = g.stamp(f, false);
        g.0.lock()
            .unwrap()
            .ports
            .insert((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5000, false), 1);
        assert_ne!(g.stamp(f, false), first);
        assert_eq!(g.stamp(f, true), (0, 0, 0));
    }
}
