use super::{Profile, Settings, new_id};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Port {
    pub id: String,
    pub name: String,
    pub number: u16,
    pub is_default: bool,
}

impl Default for Port {
    fn default() -> Self {
        Self {
            id: "default".into(),
            name: "Default".into(),
            number: 2081,
            is_default: true,
        }
    }
}

impl Settings {
    pub fn default_port(&self) -> &Port {
        self.ports
            .iter()
            .find(|port| port.is_default)
            .expect("validated default port")
    }

    pub fn port(&self, id: &str) -> Result<&Port> {
        self.ports
            .iter()
            .find(|port| port.id == id)
            .context("Xray port not found")
    }

    pub fn active_profile_removed(&self, subscription: Option<&str>) -> bool {
        self.subscriptions
            .iter()
            .any(|source| Some(source.id.as_str()) == subscription && source.active_profile_removed)
    }

    pub fn effective_port(&self, profile: &Profile) -> u16 {
        self.port(&profile.port_id)
            .expect("validated profile port")
            .number
    }

    pub fn enabled_profiles(&self) -> impl Iterator<Item = &Profile> {
        self.profiles.iter().filter(|profile| profile.enabled)
    }

    pub(super) fn validate_ports(&self) -> Result<()> {
        ensure!(
            self.ports.iter().filter(|port| port.is_default).count() == 1,
            "Xray needs exactly one Default port"
        );
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut numbers = BTreeSet::new();
        for port in &self.ports {
            ensure!(
                !port.id.is_empty() && ids.insert(&port.id),
                "Invalid or duplicate Xray port ID"
            );
            ensure!(
                !port.name.trim().is_empty() && names.insert(port.name.trim().to_lowercase()),
                "Port names must be non-empty and unique"
            );
            ensure!(
                port.number >= 1024
                    || (port.number > 0 && Some(port.number) == self.grandfathered_port),
                "Enter a port between 1024 and 65535"
            );
            ensure!(
                numbers.insert(port.number),
                "Another port already uses this number"
            );
        }
        let mut enabled = BTreeSet::new();
        for profile in &self.profiles {
            ensure!(
                ids.contains(&profile.port_id),
                "Unknown port for Xray profile {}",
                profile.name
            );
            ensure!(
                !profile.enabled || enabled.insert(&profile.port_id),
                "Two enabled profiles use the same port"
            );
        }
        Ok(())
    }

    pub fn validate_port_name(&self, id: &str, name: &str) -> Result<()> {
        self.port(id)?;
        let name = name.trim();
        ensure!(!name.is_empty(), "Enter a port name");
        let key = name.to_lowercase();
        ensure!(
            !self
                .ports
                .iter()
                .any(|port| port.id != id && port.name.trim().to_lowercase() == key),
            "Another port already uses this name"
        );
        Ok(())
    }

    pub fn rename_port(&mut self, id: &str, name: &str) -> Result<()> {
        self.validate_port_name(id, name)?;
        self.ports
            .iter_mut()
            .find(|port| port.id == id)
            .unwrap()
            .name = name.trim().into();
        Ok(())
    }

    pub fn validate_port_number(&self, id: &str, number: u16, owned: &[u16]) -> Result<()> {
        let port = self.port(id)?;
        ensure!(
            number >= 1024 || (port.number == number && Some(number) == self.grandfathered_port),
            "Enter a port between 1024 and 65535"
        );
        ensure!(
            !self
                .ports
                .iter()
                .any(|other| other.id != id && other.number == number),
            "Another port already uses this number"
        );
        if !owned.contains(&number) {
            crate::xray::runtime::check_listener_port(number)?;
        }
        Ok(())
    }

    pub fn set_port_number(&mut self, id: &str, number: u16, owned: &[u16]) -> Result<()> {
        self.validate_port_number(id, number, owned)?;
        let port = self.ports.iter_mut().find(|port| port.id == id).unwrap();
        if Some(port.number) == self.grandfathered_port && port.number != number {
            self.grandfathered_port = None;
        }
        port.number = number;
        Ok(())
    }

    pub fn next_free_port(&self, owned: &[u16]) -> Result<u16> {
        let reserved: BTreeSet<_> = self.ports.iter().map(|port| port.number).collect();
        (2082..=u16::MAX)
            .find(|number| {
                !reserved.contains(number)
                    && (owned.contains(number)
                        || crate::xray::runtime::check_listener_port(*number).is_ok())
            })
            .context("No available local SOCKS port from 2082 to 65535")
    }

    pub fn add_port(&mut self, owned: &[u16]) -> Result<String> {
        let number = self.next_free_port(owned)?;
        let names: BTreeSet<_> = self
            .ports
            .iter()
            .map(|port| port.name.trim().to_lowercase())
            .collect();
        let name = (2..)
            .map(|n| format!("Port {n}"))
            .find(|name| !names.contains(&name.to_lowercase()))
            .unwrap();
        let id = new_id();
        self.ports.push(Port {
            id: id.clone(),
            name,
            number,
            is_default: false,
        });
        Ok(id)
    }

    pub fn remove_port(&mut self, id: &str) -> Result<()> {
        ensure!(
            !self.port(id)?.is_default,
            "The Default port cannot be deleted."
        );
        let mut names = self
            .profiles
            .iter()
            .filter(|profile| profile.port_id == id)
            .map(|profile| profile.name.as_str());
        let first: Vec<_> = names.by_ref().take(3).collect();
        if !first.is_empty() {
            let remaining = names.count();
            let mut list = first.join(", ");
            if remaining != 0 {
                list.push_str(&format!(" and {remaining} more"));
            }
            let pronoun = if first.len() == 1 { "it" } else { "them" };
            bail!("Used by {list}. Unbind {pronoun} first, then delete.");
        }
        self.ports.retain(|port| port.id != id);
        Ok(())
    }

    fn enable_profile(&mut self, index: usize) -> Option<String> {
        let (before, from_index) = self.profiles.split_at_mut(index);
        let (selected, after) = from_index.split_first_mut().unwrap();
        let replaced = before
            .iter_mut()
            .chain(after)
            .find(|p| p.enabled && p.port_id == selected.port_id)
            .map(|p| {
                p.enabled = false;
                p.name.clone()
            });
        selected.enabled = true;
        if let Some(source) = self
            .subscriptions
            .iter_mut()
            .find(|source| selected.subscription.as_ref() == Some(&source.id))
        {
            source.active_profile_removed = false;
        }
        replaced
    }

    pub fn toggle_profile(&mut self, id: &str) -> Result<Option<String>> {
        let index = self
            .profiles
            .iter()
            .position(|p| p.id == id)
            .context("Xray profile not found")?;
        if self.profiles[index].enabled {
            self.profiles[index].enabled = false;
            return Ok(None);
        }
        Ok(self.enable_profile(index))
    }

    pub fn set_profile_port(&mut self, id: &str, port_id: &str) -> Result<Option<String>> {
        self.port(port_id)?;
        let index = self
            .profiles
            .iter()
            .position(|p| p.id == id)
            .context("Xray profile not found")?;
        if self.profiles[index].port_id != port_id {
            self.profiles[index].port_id = port_id.to_owned();
            if self.profiles[index].enabled {
                return Ok(self.enable_profile(index));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener, UdpSocket};

    #[test]
    fn new_ports_skip_configured_numbers_and_other_tcp_or_udp_listeners() {
        let tcp = (2082..=u16::MAX)
            .find_map(|n| TcpListener::bind((Ipv4Addr::LOCALHOST, n)).ok())
            .unwrap();
        let udp = (2082..=u16::MAX)
            .filter(|n| *n != tcp.local_addr().unwrap().port())
            .find_map(|n| UdpSocket::bind((Ipv4Addr::LOCALHOST, n)).ok())
            .unwrap();
        let occupied = [
            tcp.local_addr().unwrap().port(),
            udp.local_addr().unwrap().port(),
        ];
        let mut settings = Settings::default();
        let id = settings.add_port(&[]).unwrap();
        let added = settings.port(&id).unwrap();
        assert_eq!(added.name, "Port 2");
        assert!(!occupied.contains(&added.number));
        assert_ne!(settings.next_free_port(&[]).unwrap(), added.number);
    }
}
