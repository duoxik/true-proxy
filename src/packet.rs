//! Bounds-checked packet transformations. Checksums are calculated by the platform backend.
use crate::config::Protocol;
use anyhow::{Result, bail, ensure};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

#[derive(Clone, Copy, Debug)]
pub struct Packet {
    pub flow: FlowKey,
    pub protocol: Protocol,
    pub transport_offset: usize,
    pub payload_offset: usize,
    pub length: usize,
    pub tcp_flags: u8,
    pub tcp_sequence: u32,
}

impl Packet {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(!bytes.is_empty(), "Пустой пакет");
        let (source, destination, protocol, offset, length) = match bytes[0] >> 4 {
            4 => {
                ensure!(bytes.len() >= 20, "Обрезанный IPv4");
                let offset = (bytes[0] as usize & 15) * 4;
                let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
                ensure!(
                    offset >= 20 && length >= offset && length <= bytes.len(),
                    "Некорректная длина IPv4"
                );
                ensure!(
                    u16::from_be_bytes([bytes[6], bytes[7]]) & 0x3fff == 0,
                    "IP-фрагментация не поддерживается"
                );
                (
                    IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
                    IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])),
                    bytes[9],
                    offset,
                    length,
                )
            }
            6 => {
                ensure!(bytes.len() >= 40, "Обрезанный IPv6");
                let length = 40 + u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
                ensure!(length <= bytes.len(), "Некорректная длина IPv6");
                let mut next = bytes[6];
                let mut offset = 40;
                for _ in 0..8 {
                    if ![0, 43, 60].contains(&next) {
                        break;
                    }
                    ensure!(offset + 2 <= length, "Обрезанный extension header");
                    let size = (bytes[offset + 1] as usize + 1) * 8;
                    next = bytes[offset];
                    offset += size;
                    ensure!(offset <= length, "Некорректный extension header");
                }
                ensure!(next != 44, "IPv6-фрагментация не поддерживается");
                (
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24])?)),
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40])?)),
                    next,
                    offset,
                    length,
                )
            }
            _ => bail!("Неизвестная версия IP"),
        };
        let protocol = match protocol {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            _ => bail!("Не TCP/UDP"),
        };
        let minimum = if protocol == Protocol::Tcp { 20 } else { 8 };
        ensure!(
            offset + minimum <= length,
            "Обрезанный транспортный заголовок"
        );
        let source = SocketAddr::new(
            source,
            u16::from_be_bytes([bytes[offset], bytes[offset + 1]]),
        );
        let destination = SocketAddr::new(
            destination,
            u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]),
        );
        let (payload_offset, tcp_flags, length) = if protocol == Protocol::Tcp {
            let header = (bytes[offset + 12] as usize >> 4) * 4;
            ensure!(
                header >= 20 && offset + header <= length,
                "Некорректный TCP header"
            );
            (offset + header, bytes[offset + 13], length)
        } else {
            let udp_len = u16::from_be_bytes([bytes[offset + 4], bytes[offset + 5]]) as usize;
            ensure!(
                udp_len >= 8 && offset + udp_len <= length,
                "Некорректная длина UDP"
            );
            (offset + 8, 0, offset + udp_len)
        };
        Ok(Self {
            flow: FlowKey {
                source,
                destination,
            },
            protocol,
            transport_offset: offset,
            payload_offset,
            length,
            tcp_flags,
            tcp_sequence: if protocol == Protocol::Tcp {
                u32::from_be_bytes(bytes[offset + 4..offset + 8].try_into()?)
            } else {
                0
            },
        })
    }

    pub fn payload<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        &bytes[self.payload_offset..self.length]
    }
    pub fn is_syn(&self) -> bool {
        self.tcp_flags & 0x12 == 0x02
    }

    pub fn reflect_tcp(&self, bytes: &mut [u8], source_port: u16, destination_port: u16) {
        let (s, d, n) = if self.flow.source.is_ipv4() {
            (12, 16, 4)
        } else {
            (8, 24, 16)
        };
        for i in 0..n {
            bytes.swap(s + i, d + i);
        }
        bytes[self.transport_offset..self.transport_offset + 2]
            .copy_from_slice(&source_port.to_be_bytes());
        bytes[self.transport_offset + 2..self.transport_offset + 4]
            .copy_from_slice(&destination_port.to_be_bytes());
    }
}

pub fn udp_reply(flow: FlowKey, payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(payload.len() <= 65507, "UDP-ответ слишком большой");
    let ipv4 = flow.source.is_ipv4();
    ensure!(ipv4 == flow.destination.is_ipv4(), "Разные семейства IP");
    let offset = if ipv4 { 20 } else { 40 };
    let mut bytes = vec![0; offset + 8 + payload.len()];
    if let (IpAddr::V4(source), IpAddr::V4(destination)) = (flow.source.ip(), flow.destination.ip())
    {
        bytes[0] = 0x45;
        let len = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&len.to_be_bytes());
        bytes[6] = 0x40;
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&destination.octets());
        bytes[16..20].copy_from_slice(&source.octets());
    } else if let (IpAddr::V6(source), IpAddr::V6(destination)) =
        (flow.source.ip(), flow.destination.ip())
    {
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
        bytes[6] = 17;
        bytes[7] = 64;
        bytes[8..24].copy_from_slice(&destination.octets());
        bytes[24..40].copy_from_slice(&source.octets());
    }
    bytes[offset..offset + 2].copy_from_slice(&flow.destination.port().to_be_bytes());
    bytes[offset + 2..offset + 4].copy_from_slice(&flow.source.port().to_be_bytes());
    bytes[offset + 4..offset + 6].copy_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
    bytes[offset + 8..].copy_from_slice(payload);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tcp_reflection_preserves_sequence_and_restores_original_endpoints() {
        for (source, destination) in [
            ("192.0.2.1:51000", "203.0.113.1:443"),
            ("[2001:db8::1]:51000", "[2001:db8::2]:443"),
        ] {
            let original = FlowKey {
                source: source.parse().unwrap(),
                destination: destination.parse().unwrap(),
            };
            let response = udp_reply(original, &[0; 12]).unwrap();
            let mut bytes = response;
            let offset = if original.source.is_ipv4() { 20 } else { 40 };
            if offset == 20 {
                bytes[9] = 6;
            } else {
                bytes[6] = 6;
            }
            bytes[offset + 12] = 0x50;
            bytes[offset + 13] = 0x02;
            bytes[offset + 4..offset + 8].copy_from_slice(&12345u32.to_be_bytes());
            // Build the outgoing request from the response-shaped IP template.
            let template = Packet::parse(&bytes).unwrap();
            template.reflect_tcp(
                &mut bytes,
                original.source.port(),
                original.destination.port(),
            );
            let request = Packet::parse(&bytes).unwrap();
            assert_eq!(request.flow, original);
            assert!(request.is_syn());
            request.reflect_tcp(&mut bytes, 10001, 40000);
            let reflected = Packet::parse(&bytes).unwrap();
            assert_eq!(
                reflected.flow.source,
                SocketAddr::new(original.destination.ip(), 10001)
            );
            assert_eq!(
                reflected.flow.destination,
                SocketAddr::new(original.source.ip(), 40000)
            );
            assert_eq!(reflected.tcp_sequence, 12345);
            reflected.reflect_tcp(&mut bytes, 40000, 10001);
            let listener_reply = Packet::parse(&bytes).unwrap();
            listener_reply.reflect_tcp(
                &mut bytes,
                original.destination.port(),
                original.source.port(),
            );
            let restored = Packet::parse(&bytes).unwrap();
            assert_eq!(restored.flow.source, original.destination);
            assert_eq!(restored.flow.destination, original.source);
            assert_eq!(restored.tcp_sequence, 12345);
        }
    }
    #[test]
    fn udp_reply_swaps_endpoints() {
        for (s, d) in [
            ("192.168.1.4:5000", "1.1.1.1:53"),
            ("[2001:db8::1]:5000", "[2606:4700:4700::1111]:53"),
        ] {
            let f = FlowKey {
                source: s.parse().unwrap(),
                destination: d.parse().unwrap(),
            };
            let b = udp_reply(f, b"query").unwrap();
            let p = Packet::parse(&b).unwrap();
            assert_eq!(p.flow.source, f.destination);
            assert_eq!(p.flow.destination, f.source);
            assert_eq!(p.payload(&b), b"query");
        }
    }
    #[test]
    fn rejects_all_truncations_without_panics() {
        let f = FlowKey {
            source: "192.168.1.4:5000".parse().unwrap(),
            destination: "1.1.1.1:53".parse().unwrap(),
        };
        let b = udp_reply(f, b"abc").unwrap();
        for i in 0..b.len() {
            assert!(Packet::parse(&b[..i]).is_err());
        }
    }
    #[test]
    fn rejects_fragments() {
        let f = FlowKey {
            source: "1.1.1.1:53".parse().unwrap(),
            destination: "192.168.1.4:5000".parse().unwrap(),
        };
        let mut b = udp_reply(f, b"x").unwrap();
        b[6] = 0x20;
        assert!(Packet::parse(&b).is_err());
    }
}
