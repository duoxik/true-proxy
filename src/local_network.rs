//! Immutable highest-priority Direct destinations, shared by UI and routing.
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

/// No parsing, allocation, profile lookup, or lock in the packet path.
pub fn contains(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => matches!(
            ip.octets(),
            [10, _, _, _]
                | [172, 16..=31, _, _]
                | [192, 168, _, _]
                | [169, 254, _, _]
                | [127, _, _, _]
        ),
        IpAddr::V6(ip) => {
            let prefix = ip.segments()[0];
            prefix & 0xfe00 == 0xfc00 || prefix & 0xffc0 == 0xfe80 || ip.is_loopback()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_matcher_and_displayed_cidrs_agree_including_prefix_boundaries() {
        let networks = NETWORKS.map(|text| text.parse::<ipnet::IpNet>().unwrap());
        let mut addresses = Vec::new();
        for network in &networks {
            addresses.push(network.network());
            addresses.push(network.broadcast());
            match network {
                ipnet::IpNet::V4(network) => {
                    if let Some(previous) = u32::from(network.network()).checked_sub(1) {
                        addresses.push(std::net::Ipv4Addr::from(previous).into());
                    }
                    if let Some(next) = u32::from(network.broadcast()).checked_add(1) {
                        addresses.push(std::net::Ipv4Addr::from(next).into());
                    }
                }
                ipnet::IpNet::V6(network) => {
                    if let Some(previous) = u128::from(network.network()).checked_sub(1) {
                        addresses.push(std::net::Ipv6Addr::from(previous).into());
                    }
                    if let Some(next) = u128::from(network.broadcast()).checked_add(1) {
                        addresses.push(std::net::Ipv6Addr::from(next).into());
                    }
                }
            }
        }
        for address in [
            "0.0.0.0",
            "100.64.0.1",
            "192.0.2.1",
            "255.255.255.255",
            "::",
            "::ffff:192.168.50.1",
            "2001:db8::1",
            "ff02::1:2",
        ] {
            addresses.push(address.parse().unwrap());
        }
        for address in addresses {
            assert_eq!(
                contains(address),
                networks.iter().any(|network| network.contains(&address)),
                "{address}"
            );
        }
    }
}
