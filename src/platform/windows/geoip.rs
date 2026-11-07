//! HTTPS lookup of the exit location through a SOCKS5 proxy.
use crate::{config::Proxy, socks};
use anyhow::{Context, Result};
use schannel::{
    schannel_cred::{Direction, Protocol, SchannelCred},
    tls_stream::Builder,
};
use serde::Deserialize;
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

const HOST: &str = "ipinfo.io";
const TIME_LIMIT: Duration = Duration::from_secs(5);
const HEADER_LIMIT: u64 = 16 * 1024;
const BODY_LIMIT: usize = 8 * 1024;
const TLS_READ_LIMIT: usize = 256 * 1024;

/// Only the exit's city and country code are retained from the response.
pub async fn proxy_location(proxy: &Proxy) -> Option<String> {
    let deadline = Instant::now() + TIME_LIMIT;
    tokio::time::timeout(TIME_LIMIT, async {
        let stream = socks::connect_hostname(proxy, HOST, 443)
            .await
            .ok()?
            .into_std()
            .ok()?;
        tokio::task::spawn_blocking(move || lookup(stream, deadline).ok())
            .await
            .ok()?
    })
    .await
    .ok()?
}

fn lookup(stream: TcpStream, deadline: Instant) -> Result<String> {
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
        .domain(HOST)
        .connect(cred, socket)
        .map_err(|_| anyhow::anyhow!("GeoIP TLS handshake failed"))?;
    write!(
        stream,
        "GET /json HTTP/1.0\r\nHost: {HOST}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
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
        country: String,
        city: Option<String>,
    }
    let Location { country, city } = serde_json::from_slice(&body).ok()?;
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
