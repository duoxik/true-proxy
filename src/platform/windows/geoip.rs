//! HTTPS lookup of the exit location through a SOCKS5 proxy.
use crate::{config::Proxy, socks};
use anyhow::{Context, Result};
use schannel::{
    schannel_cred::{Direction, Protocol, SchannelCred},
    tls_stream::Builder,
};
use serde::Deserialize;
use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    io::{self, BufRead, BufReader, Read, Write},
    net::TcpStream,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

const PROVIDERS: [(&str, &str); 2] = [
    ("ipinfo.io", "/json"),
    ("ipwho.is", "/?fields=success,country_code,city"),
];
const TIME_LIMIT: Duration = Duration::from_secs(5);
const HEADER_LIMIT: u64 = 16 * 1024;
const BODY_LIMIT: usize = 8 * 1024;
const TLS_READ_LIMIT: usize = 256 * 1024;
const LOCATION_INTERVAL: Duration = Duration::from_secs(5 * 60);
const CACHE_LIMIT: usize = 64;

struct CachedLocation {
    at: Instant,
    location: Option<String>,
}
#[derive(Default)]
struct LocationCache {
    entries: HashMap<u64, CachedLocation>,
}
impl LocationCache {
    // Some(None) is a cached failure; None reserves a lookup for this caller.
    fn begin(&mut self, key: u64, now: Instant) -> Option<Option<String>> {
        if let Some(entry) = self.entries.get_mut(&key) {
            if now.saturating_duration_since(entry.at) < LOCATION_INTERVAL {
                return Some(entry.location.clone());
            }
            entry.at = now;
        } else {
            if self.entries.len() >= CACHE_LIMIT
                && let Some(oldest) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.at)
                    .map(|(&key, _)| key)
            {
                self.entries.remove(&oldest);
            }
            self.entries.insert(
                key,
                CachedLocation {
                    at: now,
                    location: None,
                },
            );
        }
        None
    }
    fn finish(&mut self, key: u64, at: Instant, location: Option<String>) -> Option<String> {
        let entry = self.entries.get_mut(&key)?;
        if entry.at == at && location.is_some() {
            entry.location = location;
        }
        entry.location.clone()
    }
}
static CACHE: OnceLock<Mutex<LocationCache>> = OnceLock::new();

/// Only the exit's city and country code are retained from the response.
pub async fn proxy_location(proxy: &Proxy) -> Option<String> {
    let mut hasher = DefaultHasher::new();
    (
        &proxy.id,
        &proxy.host,
        proxy.port,
        &proxy.username,
        &proxy.protected_password,
    )
        .hash(&mut hasher);
    let key = hasher.finish();
    let at = Instant::now();
    let cache = CACHE.get_or_init(|| Mutex::new(LocationCache::default()));
    if let Some(cached) = cache.lock().unwrap().begin(key, at) {
        return cached;
    }
    let deadline = at + TIME_LIMIT;
    let location = tokio::time::timeout(TIME_LIMIT, async {
        for (host, path) in PROVIDERS {
            let Ok(stream) = socks::connect_hostname(proxy, host, 443).await else {
                continue;
            };
            let Ok(stream) = stream.into_std() else {
                continue;
            };
            if let Ok(Ok(location)) =
                tokio::task::spawn_blocking(move || lookup(stream, deadline, host, path)).await
            {
                return Some(location);
            }
        }
        None
    })
    .await
    .ok()
    .flatten();
    cache.lock().unwrap().finish(key, at, location)
}

fn lookup(stream: TcpStream, deadline: Instant, host: &str, path: &str) -> Result<String> {
    stream.set_nonblocking(false)?;
    let socket = BoundedSocket {
        stream,
        deadline,
        remaining_bytes: TLS_READ_LIMIT,
    };
    let cred = SchannelCred::builder()
        .enabled_protocols(&[Protocol::Tls12, Protocol::Tls13])
        .acquire(Direction::Outbound)?;
    // Schannel uses the Windows trust store and verifies this hostname.
    let mut stream = Builder::new()
        .domain(host)
        .connect(cred, socket)
        .map_err(|_| anyhow::anyhow!("GeoIP TLS handshake failed"))?;
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: TrueProxy/{}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    )?;
    stream.flush()?;
    read_location(BufReader::new(stream)).context("Invalid GeoIP response")
}

/// A deadline across all raw reads and writes, including TLS handshake I/O.
struct BoundedSocket {
    stream: TcpStream,
    deadline: Instant,
    remaining_bytes: usize,
}

impl BoundedSocket {
    fn remaining_time(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .map(|duration| duration.max(Duration::from_millis(1)))
            .ok_or_else(|| io::ErrorKind::TimedOut.into())
    }
}

impl Read for BoundedSocket {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.remaining_bytes == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.stream.set_read_timeout(Some(self.remaining_time()?))?;
        let capacity = buffer.len().min(self.remaining_bytes);
        let read = self.stream.read(&mut buffer[..capacity])?;
        self.remaining_bytes -= read;
        Ok(read)
    }
}

impl Write for BoundedSocket {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream
            .set_write_timeout(Some(self.remaining_time()?))?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn read_location(mut response: impl BufRead) -> Option<String> {
    let mut headers = response.by_ref().take(HEADER_LIMIT);
    let mut line = String::new();
    headers.read_line(&mut line).ok()?;
    let mut status = line.strip_suffix("\r\n")?.split_ascii_whitespace();
    if !matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) || status.next() != Some("200") {
        return None;
    }

    let mut length = None;
    loop {
        line.clear();
        headers.read_line(&mut line).ok()?;
        let line = line.strip_suffix("\r\n")?;
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("Content-Length") {
            let size = value.trim().parse::<usize>().ok()?;
            if size > BODY_LIMIT || length.replace(size).is_some() {
                return None;
            }
        }
        if name.eq_ignore_ascii_case("Transfer-Encoding")
            || (name.eq_ignore_ascii_case("Content-Encoding")
                && !value.trim().eq_ignore_ascii_case("identity"))
        {
            return None;
        }
    }

    let body = if let Some(length) = length {
        let mut body = vec![0; length];
        response.read_exact(&mut body).ok()?;
        body
    } else {
        let mut body = Vec::new();
        response
            .take((BODY_LIMIT + 1) as u64)
            .read_to_end(&mut body)
            .ok()?;
        if body.len() > BODY_LIMIT {
            return None;
        }
        body
    };

    #[derive(Deserialize)]
    struct Location {
        country: Option<String>,
        country_code: Option<String>,
        success: Option<bool>,
        city: Option<String>,
    }
    let Location {
        country,
        country_code,
        success,
        city,
    } = serde_json::from_slice(&body).ok()?;
    if success == Some(false) || (country_code.is_some() && success != Some(true)) {
        return None;
    }
    let country = country_code.or(country)?;
    if country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    let city = city.as_deref().map(str::trim).filter(|city| {
        !city.is_empty() && city.chars().count() <= 80 && !city.chars().any(char::is_control)
    });
    Some(match city {
        Some(city) => format!("{city}, {country}"),
        None => country,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn location_checks_are_cached_for_five_minutes_and_keep_the_last_success() {
        let mut cache = LocationCache::default();
        let now = Instant::now();
        assert_eq!(cache.begin(1, now), None);
        assert_eq!(
            cache.begin(1, now),
            Some(None),
            "deduplicate in-flight requests"
        );
        cache.finish(1, now, Some("Riga, LV".into()));
        assert_eq!(
            cache.begin(1, now + Duration::from_secs(299)),
            Some(Some("Riga, LV".into()))
        );
        let next = now + Duration::from_secs(300);
        assert_eq!(cache.begin(1, next), None);
        assert_eq!(cache.finish(1, next, None), Some("Riga, LV".into()));
        assert_eq!(
            cache.begin(1, now + Duration::from_secs(599)),
            Some(Some("Riga, LV".into()))
        );
        assert_eq!(cache.begin(1, now + Duration::from_secs(600)), None);
        for key in 2..=100 {
            cache.begin(key, now);
        }
        assert!(cache.entries.len() <= CACHE_LIMIT);
    }

    #[test]
    fn fallback_accepts_a_confirmed_country_code_and_rejects_api_errors() {
        let response = |body: &str| {
            format!(
                "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        };
        assert_eq!(
            read_location(
                response(r#"{"success":true,"city":"Riga","country_code":"LV"}"#).as_bytes()
            ),
            Some("Riga, LV".into())
        );
        assert!(
            read_location(response(r#"{"success":false,"country_code":"LV"}"#).as_bytes())
                .is_none()
        );
        assert!(read_location(response(r#"{"country_code":"LV"}"#).as_bytes()).is_none());
        assert!(read_location(b"HTTP/1.0 429 Too Many Requests\r\n\r\n".as_slice()).is_none());
    }

    #[test]
    fn accepts_bounded_success_and_rejects_redirect_or_truncated_body() {
        let body = r#"{"ip":"192.0.2.1","city":"Frankfurt am Main","country":"DE"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        assert_eq!(
            read_location(response.as_bytes()).as_deref(),
            Some("Frankfurt am Main, DE")
        );
        assert!(read_location(&response.as_bytes()[..response.len() - 1]).is_none());
        assert!(read_location(response.replace("200 OK", "302 Found").as_bytes()).is_none());
        assert!(read_location(response.replace("DE", "D2").as_bytes()).is_none());
        assert!(
            read_location(b"HTTP/1.0 200 OK\r\nContent-Length: 8193\r\n\r\n".as_slice()).is_none()
        );
        assert_eq!(
            read_location(b"HTTP/1.0 200 OK\r\n\r\n{\"country\":\"DE\"}".as_slice()).as_deref(),
            Some("DE")
        );
    }
}
