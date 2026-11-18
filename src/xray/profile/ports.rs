use super::{Profile, Settings};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;

pub(super) fn next_port(reserved: &BTreeSet<u16>) -> Result<u16> {
    (2081..=u16::MAX)
        .find(|port| {
            !reserved.contains(port) && crate::xray::runtime::check_listener_port(*port).is_ok()
        })
        .context("No available local SOCKS port from 2081 to 65535")
}

impl Settings {
    pub(super) fn reserved_ports(&self) -> BTreeSet<u16> {
        self.subscriptions
            .iter()
            .map(|source| source.default_port)
            .chain([self.manual_default_port])
            .chain(
                self.profiles
                    .iter()
                    .filter_map(|profile| profile.custom_port),
            )
            .collect()
    }

    pub fn default_port(&self, container: Option<&str>) -> u16 {
        match container {
            None => self.manual_default_port,
            Some(id) => self
                .subscriptions
                .iter()
                .find(|source| source.id == id)
                .map_or(0, |source| source.default_port),
        }
    }

    pub fn active_profile_removed(&self, container: Option<&str>) -> bool {
        self.subscriptions
            .iter()
            .any(|source| Some(source.id.as_str()) == container && source.active_profile_removed)
    }

    pub fn effective_port(&self, profile: &Profile) -> u16 {
        profile
            .custom_port
            .unwrap_or_else(|| self.default_port(profile.subscription.as_deref()))
    }

    pub fn enabled_profiles(&self) -> impl Iterator<Item = &Profile> {
        self.profiles.iter().filter(|profile| profile.enabled)
    }

    pub(super) fn validate_ports(&self) -> Result<()> {
        let defaults: Vec<_> = self
            .subscriptions
            .iter()
            .map(|source| source.default_port)
            .chain([self.manual_default_port])
            .collect();
        ensure!(
            defaults
                .iter()
                .all(|port| *port >= 1024 || (*port > 0 && Some(*port) == self.grandfathered_port)),
            "Enter a default port between 1024 and 65535"
        );
        let defaults: BTreeSet<_> = defaults.into_iter().collect();
        ensure!(
            defaults.len() == self.subscriptions.len() + 1,
            "Another container already uses this default port"
        );
        let mut enabled = BTreeSet::new();
        for profile in &self.profiles {
            if let Some(port) = profile.custom_port {
                ensure!(port >= 1024, "Enter a custom port between 1024 and 65535");
                ensure!(
                    !defaults.contains(&port)
                        || port == self.default_port(profile.subscription.as_deref()),
                    "This port is reserved by another container"
                );
            }
            ensure!(
                !profile.enabled || enabled.insert(self.effective_port(profile)),
                "Two enabled profiles would use the same port. Turn one off first"
            );
        }
        Ok(())
    }

    pub fn set_default_port(&mut self, container: Option<&str>, port: u16) -> Result<()> {
        if self.default_port(container) == port && port != 0 {
            return Ok(());
        }
        ensure!(port >= 1024, "Enter a default port between 1024 and 65535");
        let mut next = self.clone();
        let target = match container {
            Some(id) => {
                &mut next
                    .subscriptions
                    .iter_mut()
                    .find(|source| source.id == id)
                    .context("Subscription not found")?
                    .default_port
            }
            None => &mut next.manual_default_port,
        };
        if next.grandfathered_port == Some(*target) {
            next.grandfathered_port = None;
        }
        *target = port;
        next.validate_ports()?;
        *self = next;
        Ok(())
    }

    pub fn set_custom_port(&mut self, id: &str, port: Option<u16>) -> Result<()> {
        let mut next = self.clone();
        next.profiles
            .iter_mut()
            .find(|profile| profile.id == id)
            .context("Xray profile not found")?
            .custom_port = port;
        next.validate_ports()?;
        *self = next;
        Ok(())
    }

    pub fn toggle_profile(&mut self, id: &str) -> Result<Option<String>> {
        let index = self
            .profiles
            .iter()
            .position(|profile| profile.id == id)
            .context("Xray profile not found")?;
        if self.profiles[index].enabled {
            self.profiles[index].enabled = false;
            return Ok(None);
        }
        let port = self.effective_port(&self.profiles[index]);
        let previous = self
            .profiles
            .iter()
            .position(|profile| profile.enabled && self.effective_port(profile) == port);
        let replaced = previous.map(|previous| {
            self.profiles[previous].enabled = false;
            self.profiles[previous].name.clone()
        });
        self.profiles[index].enabled = true;
        if let Some(source) = self
            .subscriptions
            .iter_mut()
            .find(|source| self.profiles[index].subscription.as_deref() == Some(&source.id))
        {
            source.active_profile_removed = false;
        }
        Ok(replaced)
    }

    pub(super) fn migrate_ports(&mut self, port: u16) -> Result<()> {
        ensure!(port != 0, "The saved SOCKS port is invalid");
        let target = if let Some(active) = self.legacy_active.take() {
            let profile = self
                .profiles
                .iter_mut()
                .find(|profile| profile.id == active)
                .context("The active Xray profile is missing")?;
            profile.enabled = true;
            profile.subscription.clone()
        } else if self
            .profiles
            .iter()
            .any(|profile| profile.subscription.is_none())
        {
            None
        } else {
            self.subscriptions.first().map(|source| source.id.clone())
        };
        self.grandfathered_port = (port < 1024).then_some(port);
        let mut reserved = BTreeSet::from([port]);
        let mut allocate = |owns_old_port: bool| -> Result<u16> {
            if owns_old_port {
                return Ok(port);
            }
            let next = next_port(&reserved)?;
            reserved.insert(next);
            Ok(next)
        };
        self.manual_default_port = allocate(target.is_none())?;
        for source in &mut self.subscriptions {
            source.default_port = allocate(target.as_deref() == Some(&source.id))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener, UdpSocket};

    #[test]
    fn suggestions_skip_configured_ports_and_ports_owned_on_either_protocol() {
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        for occupied in [
            tcp.local_addr().unwrap().port(),
            udp.local_addr().unwrap().port(),
        ] {
            let reserved = (2081..occupied).collect();
            let result = next_port(&reserved);
            if occupied == u16::MAX {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap() > occupied);
            }
        }
    }
}
