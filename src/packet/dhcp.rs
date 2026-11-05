//! Narrow classification of interface configuration traffic (RFC 2131/9915).
//! This is a structural classifier, not authentication of a DHCP participant.
use super::Packet;
use crate::config::Protocol;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(super) fn client_request(packet: &Packet, bytes: &[u8]) -> bool {
    if packet.protocol != Protocol::Udp || packet.length > bytes.len() {
        return false;
    }
    let Some(payload) = bytes.get(packet.payload_offset..packet.length) else {
        return false;
    };
    match (packet.flow.source.ip(), packet.flow.destination.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            packet.flow.source.port() == 68
                && packet.flow.destination.port() == 67
                && !source.is_multicast()
                && !source.is_broadcast()
                && !source.is_loopback()
                && !destination.is_unspecified()
                && !destination.is_multicast()
                && !destination.is_loopback()
                && v4(payload, source)
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            packet.flow.source.port() == 546
                && packet.flow.destination.port() == 547
                && !source.is_unspecified()
                && !source.is_multicast()
                && !source.is_loopback()
                && !destination.is_unspecified()
                && !destination.is_loopback()
                && (!destination.is_multicast()
                    || destination == Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2))
                && v6(payload)
        }
        _ => false,
    }
}

fn v4(bytes: &[u8], source: Ipv4Addr) -> bool {
    // BOOTREQUEST, a real link-layer identifier, no relay hop, and DHCP cookie.
    if bytes.len() < 244
        || bytes[0] != 1
        || bytes[1] == 0
        || !(1..=16).contains(&bytes[2])
        || bytes[3] != 0
        || bytes[16..28] != [0; 12] // yiaddr/siaddr/giaddr are zero in client requests.
        || bytes[236..240] != [99, 130, 83, 99]
    {
        return false;
    }
    let client = Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[12..16]).unwrap());
    if !client.is_unspecified() && client != source {
        return false;
    }
    let mut message = None;
    let mut options = &bytes[240..];
    while let Some((&code, rest)) = options.split_first() {
        options = rest;
        match code {
            0 => continue,
            255 => {
                // Only DHCP padding may follow END; no hidden arbitrary suffix.
                return options.iter().all(|byte| *byte == 0)
                    && match message {
                        Some(1 | 4) => client.is_unspecified() && source.is_unspecified(),
                        Some(3) => client == source,
                        Some(7 | 8) => !client.is_unspecified() && client == source,
                        _ => false,
                    };
            }
            _ => {
                let Some((&length, rest)) = options.split_first() else {
                    return false;
                };
                let Some(value) = rest.get(..length as usize) else {
                    return false;
                };
                options = &rest[length as usize..];
                if code == 53 {
                    if value.len() != 1 || message.is_some() {
                        return false;
                    }
                    message = Some(value[0]);
                }
            }
        }
    }
    false
}

fn v6(bytes: &[u8]) -> bool {
    // Client messages only: never give server or relay traffic this exception.
    if bytes.len() < 4 || !matches!(bytes[0], 1 | 3 | 4 | 5 | 6 | 8 | 9 | 11) {
        return false;
    }
    let mut client_id = false;
    let mut server_id = false;
    let mut elapsed_time = false;
    let mut options = &bytes[4..];
    while !options.is_empty() {
        if options.len() < 4 {
            return false;
        }
        let code = u16::from_be_bytes([options[0], options[1]]);
        let length = u16::from_be_bytes([options[2], options[3]]) as usize;
        let Some(value) = options.get(4..4 + length) else {
            return false;
        };
        options = &options[4 + length..];
        match code {
            1 => {
                if client_id || value.len() < 2 {
                    return false;
                }
                client_id = true;
            }
            2 => {
                if server_id || value.len() < 2 {
                    return false;
                }
                server_id = true;
            }
            8 => {
                if elapsed_time || value.len() != 2 {
                    return false;
                }
                elapsed_time = true;
            }
            9 => return false, // Relay Message is not a client option.
            _ => {}
        }
    }
    // Information-request may deliberately omit its Client Identifier.
    (client_id || bytes[0] == 11)
        && elapsed_time
        && (!matches!(bytes[0], 3 | 5 | 8 | 9) || server_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{FlowKey, udp_reply};

    fn request(source: &str, destination: &str, payload: &[u8]) -> Vec<u8> {
        udp_reply(
            FlowKey {
                source: destination.parse().unwrap(),
                destination: source.parse().unwrap(),
            },
            payload,
        )
        .unwrap()
    }
    fn classified(source: &str, destination: &str, payload: &[u8]) -> bool {
        let bytes = request(source, destination, payload);
        Packet::parse(&bytes)
            .unwrap()
            .is_dhcp_client_request(&bytes)
    }
    fn v4_request(kind: u8, address: [u8; 4]) -> Vec<u8> {
        let mut bytes = vec![0; 240];
        bytes[..3].copy_from_slice(&[1, 1, 6]);
        bytes[12..16].copy_from_slice(&address);
        bytes[28..34].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        bytes[236..240].copy_from_slice(&[99, 130, 83, 99]);
        bytes.extend_from_slice(&[53, 1, kind, 255]);
        bytes.resize(300, 0);
        bytes
    }
    fn v6_request(kind: u8) -> Vec<u8> {
        let mut bytes = vec![kind, 0x12, 0x34, 0x56];
        // DUID-LL client/server identifiers, Elapsed Time, Option Request.
        if kind != 11 {
            bytes.extend_from_slice(&[0, 1, 0, 10, 0, 3, 0, 1, 2, 0, 0, 0, 0, 1]);
        }
        if matches!(kind, 3 | 5 | 8 | 9) {
            bytes.extend_from_slice(&[0, 2, 0, 10, 0, 3, 0, 1, 2, 0, 0, 0, 0, 2]);
        }
        bytes.extend_from_slice(&[0, 8, 0, 2, 0, 0, 0, 6, 0, 4, 0, 23, 0, 24]);
        bytes
    }

    #[test]
    fn acquisition_renewal_rebind_release_and_inform_are_interface_traffic() {
        for (kind, source, destination, address) in [
            (1, "0.0.0.0:68", "255.255.255.255:67", [0; 4]),
            (3, "0.0.0.0:68", "255.255.255.255:67", [0; 4]),
            (4, "0.0.0.0:68", "255.255.255.255:67", [0; 4]),
            (3, "192.0.2.30:68", "192.0.2.1:67", [192, 0, 2, 30]),
            (3, "192.0.2.30:68", "255.255.255.255:67", [192, 0, 2, 30]),
            (7, "192.0.2.30:68", "192.0.2.1:67", [192, 0, 2, 30]),
            (8, "192.0.2.30:68", "192.0.2.1:67", [192, 0, 2, 30]),
        ] {
            assert!(classified(source, destination, &v4_request(kind, address)));
        }
    }

    #[test]
    fn dhcp_ports_do_not_exempt_other_udp_invalid_messages_or_server_packets() {
        let payload = v4_request(3, [192, 0, 2, 30]);
        for (source, destination) in [
            ("192.0.2.30:5000", "192.0.2.1:67"),
            ("192.0.2.30:68", "192.0.2.1:443"),
            ("192.0.2.30:67", "192.0.2.1:68"),
            ("192.0.2.30:68", "224.0.0.1:67"),
            ("192.0.2.30:68", "0.0.0.0:67"),
            ("192.0.2.31:68", "192.0.2.1:67"),
        ] {
            assert!(!classified(source, destination, &payload));
        }
        for i in 0..244 {
            assert!(!classified("192.0.2.30:68", "192.0.2.1:67", &payload[..i]));
        }
        for (at, byte) in [(0, 2), (3, 1), (236, 0), (242, 2), (243, 1), (299, 1)] {
            let mut broken = payload.clone();
            broken[at] = byte;
            assert!(!classified("192.0.2.30:68", "192.0.2.1:67", &broken));
        }
        assert!(!classified(
            "192.0.2.30:68",
            "192.0.2.1:67",
            b"ordinary application traffic"
        ));
        let mut duplicate = payload[..243].to_vec();
        duplicate.extend_from_slice(&[53, 1, 3, 255]);
        assert!(!classified("192.0.2.30:68", "192.0.2.1:67", &duplicate));
    }

    #[test]
    fn ipv6_client_messages_support_multicast_and_legacy_unicast() {
        for kind in [1, 3, 4, 5, 6, 8, 9, 11] {
            for destination in ["[ff02::1:2]:547", "[fe80::1]:547", "[2001:db8::1]:547"] {
                assert!(classified("[fe80::30]:546", destination, &v6_request(kind)));
            }
        }
    }

    #[test]
    fn ipv6_requires_client_shape_complete_options_and_dhcp_multicast_group() {
        let payload = v6_request(1);
        for kind in [0, 2, 7, 10, 12, 13, 255] {
            let mut broken = payload.clone();
            broken[0] = kind;
            assert!(!classified("[fe80::30]:546", "[ff02::1:2]:547", &broken));
        }
        for (source, destination) in [
            ("[fe80::30]:5000", "[ff02::1:2]:547"),
            ("[fe80::30]:546", "[ff02::1:3]:547"),
            ("[::]:546", "[ff02::1:2]:547"),
            ("[ff02::1:2]:546", "[fe80::1]:547"),
        ] {
            assert!(!classified(source, destination, &payload));
        }
        for tail in [
            &[0][..],
            &[0, 9, 0, 0],
            &[0, 1, 0, 2, 0, 3],
            &[0, 20, 0, 10, 1],
        ] {
            let mut broken = payload.clone();
            broken.extend_from_slice(tail);
            assert!(!classified("[fe80::30]:546", "[ff02::1:2]:547", &broken));
        }
        let mut no_server_id = v6_request(1);
        no_server_id[0] = 5;
        assert!(!classified(
            "[fe80::30]:546",
            "[ff02::1:2]:547",
            &no_server_id
        ));
    }
}
