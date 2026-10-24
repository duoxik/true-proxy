use anyhow::Context;
use anyhow::{Result, bail, ensure};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

fn u16_at(bytes: &[u8], at: usize) -> Result<u16> {
    ensure!(at + 2 <= bytes.len(), "Обрезанный DNS");
    Ok(u16::from_be_bytes([bytes[at], bytes[at + 1]]))
}

/// Forward one DNS message over a SOCKS5 TCP stream, with no local DNS fallback.
pub async fn exchange(
    proxy: &crate::config::Proxy,
    resolver: IpAddr,
    query: &[u8],
) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    ensure!(
        (12..=65535).contains(&query.len()),
        "Некорректный DNS-запрос"
    );
    tokio::time::timeout(Duration::from_secs(8), async {
        let mut stream =
            crate::socks::connect(proxy, std::net::SocketAddr::new(resolver, 53)).await?;
        stream.write_u16(query.len() as u16).await?;
        stream.write_all(query).await?;
        let len = stream.read_u16().await? as usize;
        ensure!(len >= 12, "Обрезанный DNS-ответ");
        let mut response = vec![0; len];
        stream.read_exact(&mut response).await?;
        ensure!(
            response[..2] == query[..2] && response[2] & 0x80 != 0,
            "DNS-сервер вернул неверный ID ответа"
        );
        ensure!(
            questions(&response)? == questions(query)?,
            "DNS-сервер вернул ответ на другой вопрос"
        );
        Ok(response)
    })
    .await
    .context("Таймаут DNS через SOCKS5")?
}

fn name(bytes: &[u8], cursor: &mut usize) -> Result<String> {
    let mut at = *cursor;
    let mut jumped = false;
    let mut labels = Vec::new();
    let mut size = 0;
    for _ in 0..128 {
        ensure!(at < bytes.len(), "Обрезанное DNS-имя");
        let len = bytes[at];
        if len & 0xc0 == 0xc0 {
            let target = (u16_at(bytes, at)? & 0x3fff) as usize;
            ensure!(target < at, "Некорректный DNS compression pointer");
            if !jumped {
                *cursor = at + 2;
                jumped = true;
            }
            at = target;
            continue;
        }
        ensure!(len & 0xc0 == 0 && len <= 63, "Некорректный DNS label");
        at += 1;
        if len == 0 {
            if !jumped {
                *cursor = at;
            }
            return Ok(labels.join("."));
        }
        let end = at + len as usize;
        ensure!(end <= bytes.len(), "Обрезанный DNS label");
        let label = std::str::from_utf8(&bytes[at..end])?.to_ascii_lowercase();
        ensure!(
            label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "Неподдерживаемое DNS-имя"
        );
        size += label.len() + 1;
        ensure!(size <= 254, "Слишком длинное DNS-имя");
        labels.push(label);
        at = end;
    }
    bail!("Слишком много DNS compression pointers")
}

pub fn questions(bytes: &[u8]) -> Result<Vec<String>> {
    ensure!(bytes.len() >= 12, "Обрезанный DNS header");
    let count = u16_at(bytes, 4)?;
    ensure!(count <= 16, "Слишком много DNS-вопросов");
    let mut cursor = 12;
    let mut names = Vec::new();
    for _ in 0..count {
        names.push(name(bytes, &mut cursor)?);
        ensure!(cursor + 4 <= bytes.len(), "Обрезанный DNS question");
        cursor += 4;
    }
    Ok(names)
}

pub fn answers(bytes: &[u8]) -> Result<Vec<(IpAddr, String, u32)>> {
    ensure!(
        bytes.len() >= 12 && bytes[2] & 0x80 != 0 && bytes[3] & 0x0f == 0,
        "Неуспешный DNS-ответ"
    );
    let qcount = u16_at(bytes, 4)?;
    let acount = u16_at(bytes, 6)?;
    ensure!(qcount <= 16 && acount <= 256, "Слишком большой DNS-ответ");
    let mut at = 12;
    for _ in 0..qcount {
        name(bytes, &mut at)?;
        ensure!(at + 4 <= bytes.len(), "Обрезанный DNS question");
        at += 4;
    }
    let mut result = Vec::new();
    let mut aliases = Vec::new();
    for _ in 0..acount {
        let owner = name(bytes, &mut at)?;
        ensure!(at + 10 <= bytes.len(), "Обрезанный DNS answer");
        let kind = u16_at(bytes, at)?;
        let class = u16_at(bytes, at + 2)?;
        let ttl = u32::from_be_bytes(bytes[at + 4..at + 8].try_into()?);
        let len = u16_at(bytes, at + 8)? as usize;
        at += 10;
        let end = at + len;
        ensure!(end <= bytes.len(), "Обрезанный DNS RDATA");
        if class == 1 {
            match kind {
                1 if len == 4 => result.push((
                    IpAddr::V4(Ipv4Addr::new(
                        bytes[at],
                        bytes[at + 1],
                        bytes[at + 2],
                        bytes[at + 3],
                    )),
                    owner,
                    ttl,
                )),
                28 if len == 16 => result.push((
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[at..end])?)),
                    owner,
                    ttl,
                )),
                5 => {
                    let mut p = at;
                    let target = name(bytes, &mut p)?;
                    ensure!(p <= end, "Некорректный CNAME");
                    aliases.push((owner, target, ttl));
                }
                _ => {}
            }
        }
        at = end;
    }
    // Propagate aliases through the bounded answer chain without associating unrelated RRs.
    for _ in 0..aliases.len().min(16) {
        let mut additions = Vec::new();
        for (alias, target, ttl) in &aliases {
            for (ip, owner, record_ttl) in &result {
                if owner == target && !result.iter().any(|(i, n, _)| i == ip && n == alias) {
                    additions.push((*ip, alias.clone(), (*ttl).min(*record_ttl)));
                }
            }
        }
        if additions.is_empty() {
            break;
        }
        result.extend(additions);
    }
    Ok(result)
}

#[derive(Default)]
pub struct DomainCache {
    entries: HashMap<IpAddr, Vec<(String, Instant)>>,
}

impl DomainCache {
    pub fn observe(&mut self, response: &[u8]) {
        if let Ok(answers) = answers(response) {
            let now = Instant::now();
            if self.entries.len() >= 4096 {
                self.entries.retain(|_, v| v.iter().any(|(_, e)| *e > now));
            }
            for (ip, name, ttl) in answers {
                if ttl == 0 || (self.entries.len() >= 4096 && !self.entries.contains_key(&ip)) {
                    continue;
                }
                let entries = self.entries.entry(ip).or_default();
                entries.retain(|(n, e)| n != &name && *e > now);
                if entries.len() < 16 {
                    entries.push((name, now + Duration::from_secs(ttl.min(3600) as u64)));
                }
            }
        }
    }
    pub fn lookup(&self, ip: IpAddr) -> Vec<String> {
        let now = Instant::now();
        self.entries
            .get(&ip)
            .map(|v| {
                v.iter()
                    .filter(|(_, e)| *e > now)
                    .map(|(n, _)| n.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Passive DNS-over-TCP framing. A gap disables observation until a new flow;
/// it never changes or delays the actual DNS stream.
#[derive(Default)]
pub struct TcpDnsBuffer {
    next: Option<u32>,
    bytes: Vec<u8>,
    broken: bool,
}
impl TcpDnsBuffer {
    pub fn with_sequence(sequence: u32) -> Self {
        Self {
            next: Some(sequence),
            ..Default::default()
        }
    }
    pub fn feed(&mut self, sequence: u32, mut payload: &[u8]) -> Vec<Vec<u8>> {
        if self.broken || payload.is_empty() {
            return vec![];
        }
        if let Some(next) = self.next {
            let delta = sequence.wrapping_sub(next) as i32;
            if delta > 0 {
                self.bytes.clear();
                self.broken = true;
                return vec![];
            }
            if delta < 0 {
                let overlap = (-i64::from(delta)) as usize;
                if overlap >= payload.len() {
                    return vec![];
                }
                payload = &payload[overlap..];
            }
        }
        self.next = Some(
            self.next
                .unwrap_or(sequence)
                .wrapping_add(payload.len() as u32),
        );
        if self.bytes.len() + payload.len() > 131074 {
            self.bytes.clear();
            self.broken = true;
            return vec![];
        }
        self.bytes.extend_from_slice(payload);
        let mut messages = Vec::new();
        while self.bytes.len() >= 2 {
            let size = u16::from_be_bytes([self.bytes[0], self.bytes[1]]) as usize;
            if size < 12 {
                self.bytes.clear();
                self.broken = true;
                break;
            }
            if self.bytes.len() < size + 2 {
                break;
            }
            messages.push(self.bytes[2..size + 2].to_vec());
            self.bytes.drain(..size + 2);
        }
        messages
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response() -> Vec<u8> {
        let mut b = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        b.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        b.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        b
    }
    #[test]
    fn reads_compressed_answers_and_caches() {
        let b = response();
        assert_eq!(questions(&b).unwrap(), vec!["example.com"]);
        let a = answers(&b).unwrap();
        assert_eq!(a[0].0, "1.2.3.4".parse::<IpAddr>().unwrap());
        let mut c = DomainCache::default();
        c.observe(&b);
        assert_eq!(c.lookup(a[0].0), vec!["example.com"]);
    }
    #[test]
    fn malformed_input_never_panics() {
        let b = response();
        for i in 0..b.len() {
            let _ = questions(&b[..i]);
            assert!(answers(&b[..i]).is_err());
        }
    }
    #[test]
    fn compression_cycle_is_rejected() {
        let b = [0xc0, 0];
        assert!(name(&b, &mut 0).is_err());
    }
    #[test]
    fn tcp_answers_are_observed_across_segments_and_retransmissions() {
        let response = response();
        let mut framed = (response.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&response);
        let mut tcp = TcpDnsBuffer::default();
        assert!(tcp.feed(100, &framed[..1]).is_empty());
        assert!(tcp.feed(100, &framed[..1]).is_empty());
        assert!(tcp.feed(101, &framed[1..10]).is_empty());
        let messages = tcp.feed(110, &framed[10..]);
        assert_eq!(messages, [response]);
        let mut cache = DomainCache::default();
        cache.observe(&messages[0]);
        assert_eq!(cache.lookup("1.2.3.4".parse().unwrap()), ["example.com"]);
        assert!(tcp.feed(110, &framed[10..]).is_empty());
    }
    #[test]
    fn tcp_gaps_do_not_create_false_domain_associations() {
        let mut tcp = TcpDnsBuffer::default();
        assert!(tcp.feed(100, &[0]).is_empty());
        assert!(tcp.feed(200, &[12, 0, 0, 0]).is_empty());
        assert!(tcp.feed(101, &[12, 0, 0, 0]).is_empty());
    }
}
