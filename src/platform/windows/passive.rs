//! Read-only TCP observation while the routing engine is stopped.
use super::process::{self, Process};
use crate::{
    config::{Action, Config, Protocol},
    connections::{Connection, Connections, HistoryEvent, Info, MAX_ACTIVE, Status},
    packet::FlowKey,
    rules::{self, Flow},
};
use anyhow::Result;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

type SocketKey = (u32, FlowKey);

#[derive(Default)]
pub struct PassiveConnections {
    live: HashMap<SocketKey, Connection>,
    processes: HashMap<u32, Process>,
    last_sample: Option<HistoryEvent>,
    profile: Option<Config>,
}

impl PassiveConnections {
    pub fn sample(
        &mut self,
        config: &Config,
        activity: &Arc<Connections>,
        expected: HistoryEvent,
    ) -> Result<()> {
        let event = activity.history_event();
        if !activity.is_observing(expected) || !activity.is_observing(event) {
            return Ok(());
        }
        if self
            .last_sample
            .is_some_and(|last| !activity.is_observing(last))
        {
            self.clear();
        }

        let mut observed = HashMap::new();
        let mut new_sockets = Vec::new();
        let own_pid = std::process::id();
        for ipv4 in [true, false] {
            process::visit_live_tcp(ipv4, |flow, pid, status| {
                if pid == 0 || pid == own_pid {
                    return Ok(());
                }
                let key = (pid, flow);
                let tracked = self.live.contains_key(&key);
                if observed.len() == MAX_ACTIVE && !observed.contains_key(&key) {
                    // Prefer already-observed sockets so hitting the limit cannot
                    // make an existing connection appear to have closed.
                    if !tracked {
                        return Ok(());
                    }
                    let Some(replaced) = new_sockets.pop() else {
                        return Ok(());
                    };
                    observed.remove(&replaced);
                }
                if observed.insert(key, status).is_none() && !tracked {
                    new_sockets.push(key);
                }
                Ok(())
            })?;
        }
        if !activity.is_observing(event) {
            self.clear();
            return Ok(());
        }
        self.apply(config, activity, event, observed);
        Ok(())
    }

    fn apply(
        &mut self,
        config: &Config,
        activity: &Arc<Connections>,
        event: HistoryEvent,
        mut observed: HashMap<SocketKey, Status>,
    ) {
        let profile_changed = self.profile.as_ref().is_none_or(|last| {
            last.rules != config.rules
                || last.proxies != config.proxies
                || last.default_action != config.default_action
                || last.local_networks != config.local_networks
        });
        if profile_changed {
            self.profile = Some(config.clone());
        }
        if let Some(last_sample) = self.last_sample.replace(event) {
            self.live.retain(|key, row| {
                let previous = row.status();
                let Some(status) = observed.get(key).copied() else {
                    // Disappearance is only known to have happened between samples.
                    row.finish_since(Status::Closed, "TCP socket closed", last_sample);
                    return false;
                };
                if (status == Status::Connecting && previous == Status::Active)
                    || (previous == Status::Closing && status != Status::Closing)
                {
                    row.finish_since(Status::Closed, "TCP socket replaced", last_sample);
                    return false;
                }
                if profile_changed || previous.finished() {
                    row.discard();
                    return false;
                }
                observed.remove(key);
                match status {
                    Status::Active => row.active(),
                    Status::Closing => row.closing(),
                    _ => {}
                }
                true
            });
        }
        let present_pids: HashSet<_> = self
            .live
            .keys()
            .chain(observed.keys())
            .map(|&(pid, _)| pid)
            .collect();
        self.processes.retain(|pid, _| present_pids.contains(pid));
        for ((pid, flow), status) in observed {
            if self.live.len() >= MAX_ACTIVE || !activity.is_observing(event) {
                break;
            }
            let process = self.processes.entry(pid).or_insert_with(|| {
                process::identify_pid(pid).unwrap_or_else(|_| Process {
                    pid,
                    name: format!("PID {pid}"),
                    path: String::new(),
                })
            });
            let info = describe(config, process, flow);
            if let Some(connection) = activity.start_passive(info, status, event) {
                self.live.insert((pid, flow), connection);
            } else {
                break;
            }
        }
    }

    pub fn clear(&mut self) {
        for row in self.live.drain().map(|(_, row)| row) {
            row.discard();
        }
        self.processes.clear();
        self.profile = None;
        self.last_sample = None;
    }
}

fn describe(config: &Config, process: &Process, socket: FlowKey) -> Info {
    let flow = Flow {
        process_name: &process.name,
        process_path: &process.path,
        destination: socket.destination,
        protocol: Protocol::Tcp,
        domains: &[],
    };
    let action = rules::resolve(config, &flow);
    let route = match &action {
        Action::Direct => "Direct".into(),
        Action::Block => "Block".into(),
        Action::Proxy(id) => config
            .proxy(id)
            .map(|proxy| proxy.name.clone())
            .unwrap_or_else(|_| "—".into()),
    };
    Info {
        pid: process.pid,
        process: process.name.clone(),
        source: socket.source,
        destination: socket.destination,
        protocol: Protocol::Tcp,
        route,
        detail: format!(
            "Routing paused · configured route · {}",
            rules::explanation(config, &flow)
        ),
        action,
        stamp: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paused_tcp_uses_configured_route_and_never_backfills_an_uncertain_close() {
        let mut config = Config {
            default_action: Action::Proxy("vpn".into()),
            ..Config::default()
        };
        config.proxies.push(crate::config::Proxy {
            id: "vpn".into(),
            name: "Office".into(),
            host: "localhost".into(),
            port: 1080,
            username: String::new(),
            protected_password: None,
        });
        let activity = Arc::new(Connections::default());
        activity.set_tracking(true);
        let mut observer = PassiveConnections::default();
        observer.processes.insert(
            1234,
            Process {
                pid: 1234,
                name: "browser.exe".into(),
                path: String::new(),
            },
        );
        let socket = |port| {
            (
                1234,
                FlowKey {
                    source: ([192, 0, 2, 1], port).into(),
                    destination: ([198, 51, 100, 2], 443).into(),
                },
            )
        };
        observer.apply(
            &config,
            &activity,
            activity.history_event(),
            HashMap::from([
                (socket(1024), Status::Connecting),
                (socket(1025), Status::Active),
            ]),
        );
        let rows = activity.snapshots();
        let original = rows
            .iter()
            .find(|row| row.info.source.port() == 1024)
            .unwrap();
        assert_eq!(original.info.route, "Office");
        assert_eq!(original.info.action, Action::Proxy("vpn".into()));
        assert!(original.info.detail.starts_with("Routing paused"));

        activity.set_history_statuses(&[Status::Closed]);
        observer.apply(
            &config,
            &activity,
            activity.history_event(),
            HashMap::from([(socket(1024), Status::Active)]),
        );
        let rows = activity.snapshots();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, original.id);
        assert_eq!(rows[0].status, Status::Active);

        observer.apply(&config, &activity, activity.history_event(), HashMap::new());
        let rows = activity.snapshots();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, original.id);
        assert_eq!(rows[0].status, Status::Closed);
    }
}
