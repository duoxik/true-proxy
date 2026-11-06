//! Highest-priority Direct destinations and their legacy defaults.
use ipnet::IpNet;
use std::net::IpAddr;

pub const NETWORKS: [&str; 8] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "127.0.0.0/8",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
];

pub fn default_networks() -> Vec<IpNet> {
    NETWORKS
        .iter()
        .map(|network| network.parse().unwrap())
        .collect()
}

pub fn is_default(networks: &[IpNet]) -> bool {
    networks.len() == NETWORKS.len()
        && networks
            .iter()
            .zip(NETWORKS)
            .all(|(network, default)| *network == default.parse::<IpNet>().unwrap())
}

/// Match already parsed networks from the active configuration snapshot.
pub fn contains(networks: &[IpNet], ip: IpAddr) -> bool {
    networks.iter().any(|network| network.contains(&ip))
}
