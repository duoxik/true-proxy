use crate::{
    packet::FlowKey,
    platform::windows::{divert::Address, process::Process},
};
use std::{
    collections::{HashMap, VecDeque},
    mem,
    time::{Duration, Instant},
};

const WAIT: Duration = Duration::from_secs(3);
const RETRY: Duration = Duration::from_millis(250);
const MAX_FLOWS: usize = 64;
const MAX_PACKETS_PER_FLOW: usize = 16;
const MAX_BYTES: usize = 2 * 1024 * 1024;

type Key = (FlowKey, bool);

pub(super) struct HeldPacket {
    pub(super) bytes: Vec<u8>,
    pub(super) address: Address,
}

pub(super) struct Resolved {
    pub(super) owner: Option<Process>,
    pub(super) packets: VecDeque<HeldPacket>,
}

struct PendingFlow {
    deadline: Instant,
    check_at: Instant,
    syn: Option<u32>,
    bytes: usize,
    packets: VecDeque<HeldPacket>,
}

#[derive(Default)]
pub(super) struct Pending {
    flows: HashMap<Key, PendingFlow>,
    bytes: usize,
    next_check: Option<Instant>,
}

impl Pending {
    pub(super) fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub(super) fn len(&self) -> usize {
        self.flows.len()
    }

    pub(super) fn contains(&self, key: Key) -> bool {
        self.flows.contains_key(&key)
    }

    pub(super) fn next_check(&self) -> Option<Instant> {
        self.next_check
    }

    pub(super) fn hold(
        &mut self,
        key: Key,
        bytes: &[u8],
        address: Address,
        syn: Option<u32>,
        now: Instant,
    ) -> bool {
        // A different SYN sequence on the same tuple starts a new TCP connection.
        if syn.is_some()
            && self.flows.get(&key).is_some_and(|flow| flow.syn != syn)
            && let Some(old) = self.flows.remove(&key)
        {
            self.bytes -= old.bytes;
            self.next_check = self.flows.values().map(|flow| flow.check_at).min();
        }
        if bytes.len() > MAX_BYTES - self.bytes
            || (self.flows.len() >= MAX_FLOWS && !self.flows.contains_key(&key))
        {
            return false;
        }
        let flow = self.flows.entry(key).or_insert_with(|| PendingFlow {
            deadline: now + WAIT,
            check_at: now + RETRY,
            syn,
            bytes: 0,
            packets: VecDeque::new(),
        });
        if flow.packets.len() >= MAX_PACKETS_PER_FLOW {
            return false;
        }
        flow.packets.push_back(HeldPacket {
            bytes: bytes.to_vec(),
            address,
        });
        flow.bytes += bytes.len();
        self.bytes += bytes.len();
        self.next_check = Some(
            self.next_check
                .map_or(flow.check_at, |at| at.min(flow.check_at)),
        );
        true
    }

    pub(super) fn poll(
        &mut self,
        now: Instant,
        mut identify: impl FnMut(FlowKey, bool) -> Option<Process>,
    ) -> Vec<Resolved> {
        let mut ready = Vec::new();
        if self.next_check.is_none_or(|at| now < at) {
            return ready;
        }
        let mut next_check = None;
        self.flows.retain(|&key, flow| {
            if now >= flow.check_at {
                let owner = identify(key.0, key.1);
                if owner.is_some() || now >= flow.deadline {
                    self.bytes -= flow.bytes;
                    ready.push(Resolved {
                        owner,
                        packets: mem::take(&mut flow.packets),
                    });
                    return false;
                }
                flow.check_at = (now + RETRY).min(flow.deadline);
            }
            next_check =
                Some(next_check.map_or(flow.check_at, |at: Instant| at.min(flow.check_at)));
            true
        });
        self.next_check = next_check;
        ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(port: u16, tcp: bool) -> Key {
        (
            FlowKey {
                source: ([192, 0, 2, 30], port).into(),
                destination: ([203, 0, 113, 1], 443).into(),
            },
            tcp,
        )
    }

    fn bytes(resolved: &Resolved) -> Vec<u8> {
        resolved
            .packets
            .iter()
            .map(|packet| packet.bytes[0])
            .collect()
    }

    #[test]
    fn resolves_identified_owner_and_returns_packets_in_capture_order() {
        let mut pending = Pending::default();
        let now = Instant::now();
        let key = flow(5000, true);
        let address = Address::default();
        assert!(pending.hold(key, &[1], address, Some(100), now));
        assert!(pending.hold(key, &[2], address, Some(100), now));
        assert!(pending.hold(key, &[3], address, None, now));
        assert!(pending.contains(key));
        assert_eq!(pending.next_check(), Some(now + RETRY));
        assert!(
            pending
                .poll(now, |_, _| panic!("Retry was not due"))
                .is_empty()
        );
        let ready = pending.poll(now + RETRY, |flow, tcp| {
            assert_eq!((flow, tcp), key);
            Some(Process {
                pid: 42,
                ..Process::default()
            })
        });
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].owner.as_ref().map(|owner| owner.pid), Some(42));
        assert_eq!(bytes(&ready[0]), [1, 2, 3]);
        assert!(pending.is_empty());
        assert_eq!(pending.next_check(), None);
        assert_eq!(pending.bytes, 0);
    }

    #[test]
    fn each_flow_waits_three_seconds_from_its_first_packet() {
        let mut pending = Pending::default();
        let now = Instant::now();
        let tcp = flow(5000, true);
        let udp = flow(5000, false);
        let address = Address::default();
        assert!(pending.hold(tcp, &[1], address, Some(100), now));
        assert!(pending.hold(udp, &[2], address, None, now + RETRY));
        let before_deadline = now + WAIT - Duration::from_millis(1);
        assert!(pending.poll(before_deadline, |_, _| None).is_empty());
        assert!(pending.hold(tcp, &[3], address, Some(100), before_deadline));
        assert_eq!(pending.next_check(), Some(now + WAIT));
        let ready = pending.poll(now + WAIT, |flow, is_tcp| {
            assert_eq!((flow, is_tcp), tcp);
            None
        });
        assert_eq!(ready.len(), 1);
        assert!(ready[0].owner.is_none());
        assert_eq!(bytes(&ready[0]), [1, 3]);
        assert_eq!(
            pending.next_check(),
            Some(now + WAIT + RETRY - Duration::from_millis(1))
        );
        let ready = pending.poll(now + WAIT + RETRY, |flow, is_tcp| {
            assert_eq!((flow, is_tcp), udp);
            None
        });
        assert_eq!(ready.len(), 1);
        assert_eq!(bytes(&ready[0]), [2]);
        assert!(pending.is_empty());
    }

    #[test]
    fn new_syn_replaces_held_packets_with_a_fresh_deadline() {
        let mut pending = Pending::default();
        let now = Instant::now();
        let key = flow(5000, true);
        let address = Address::default();
        assert!(pending.hold(key, &[1], address, Some(100), now));
        assert!(pending.hold(key, &[2], address, Some(200), now + RETRY));
        assert_eq!(pending.bytes, 1);
        assert_eq!(pending.next_check(), Some(now + RETRY * 2));
        assert!(pending.poll(now + WAIT, |_, _| None).is_empty());
        let ready = pending.poll(now + WAIT + RETRY, |_, _| None);
        assert_eq!(ready.len(), 1);
        assert_eq!(bytes(&ready[0]), [2]);
    }

    #[test]
    fn caps_pending_flows_packets_and_bytes() {
        let mut pending = Pending::default();
        let now = Instant::now();
        let address = Address::default();
        let key = flow(5000, false);
        for _ in 0..MAX_PACKETS_PER_FLOW {
            assert!(pending.hold(key, &[0], address, None, now));
        }
        assert!(!pending.hold(key, &[0], address, None, now));
        for port in 5001..5000 + MAX_FLOWS as u16 {
            assert!(pending.hold(flow(port, false), &[0], address, None, now));
        }
        assert!(!pending.hold(flow(6000, false), &[0], address, None, now));
        assert_eq!(pending.len(), MAX_FLOWS);
        assert_eq!(pending.poll(now + WAIT, |_, _| None).len(), MAX_FLOWS);
        let large_packet = vec![0; MAX_BYTES / MAX_FLOWS];
        for port in 5000..5000 + MAX_FLOWS as u16 {
            assert!(pending.hold(flow(port, false), &large_packet, address, None, now));
        }
        assert!(!pending.hold(key, &[0], address, None, now));
        assert!(!pending.hold(flow(6000, false), &[0], address, None, now));
        assert_eq!(pending.poll(now + WAIT, |_, _| None).len(), MAX_FLOWS);
        assert_eq!(pending.bytes, 0);
    }
}
