//! SOCKS5 transport. A failed handshake never falls back to a direct socket.
use crate::config::Proxy;
use anyhow::{Context, Result, bail, ensure};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};

const TIMEOUT: Duration = Duration::from_secs(8);

async fn negotiate(proxy: &Proxy) -> Result<TcpStream> {
    let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .context("SOCKS5-сервер недоступен")?;
    stream.set_nodelay(true)?;
    let password = proxy.password()?;
    let authenticated = !proxy.username.is_empty() || password.is_some();
    let method = if authenticated { 2 } else { 0 };
    stream.write_all(&[5, 1, method]).await?;
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).await?;
    ensure!(
        reply == [5, method],
        "SOCKS5-сервер отклонил метод аутентификации"
    );
    if authenticated {
        let password = password.as_deref().unwrap_or("");
        ensure!(
            proxy.username.len() <= 255 && password.len() <= 255,
            "Логин или пароль SOCKS5 длиннее 255 байт"
        );
        let mut auth = vec![1, proxy.username.len() as u8];
        auth.extend_from_slice(proxy.username.as_bytes());
        auth.push(password.len() as u8);
        auth.extend_from_slice(password.as_bytes());
        stream.write_all(&auth).await?;
        auth.fill(0);
        stream.read_exact(&mut reply).await?;
        ensure!(reply == [1, 0], "Неверный логин или пароль SOCKS5");
    }
    Ok(stream)
}

pub fn encode_address(address: SocketAddr, buffer: &mut Vec<u8>) {
    match address.ip() {
        IpAddr::V4(ip) => {
            buffer.push(1);
            buffer.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buffer.push(4);
            buffer.extend_from_slice(&ip.octets());
        }
    }
    buffer.extend_from_slice(&address.port().to_be_bytes());
}

async fn command(proxy: &Proxy, cmd: u8, target: SocketAddr) -> Result<(TcpStream, SocketAddr)> {
    let mut stream = negotiate(proxy).await?;
    let mut request = vec![5, cmd, 0];
    encode_address(target, &mut request);
    stream.write_all(&request).await?;
    let mut head = [0; 4];
    stream.read_exact(&mut head).await?;
    ensure!(head[0] == 5 && head[2] == 0, "Некорректный ответ SOCKS5");
    ensure!(
        head[1] == 0,
        "SOCKS5: {}",
        match head[1] {
            1 => "общая ошибка сервера",
            2 => "соединение запрещено",
            3 => "сеть недоступна",
            4 => "узел недоступен",
            5 => "соединение отклонено",
            7 => "команда не поддерживается (проверьте UDP ASSOCIATE)",
            _ => "сервер отказал в соединении",
        }
    );
    let ip = match head[3] {
        1 => {
            let mut b = [0; 4];
            stream.read_exact(&mut b).await?;
            IpAddr::V4(Ipv4Addr::from(b))
        }
        4 => {
            let mut b = [0; 16];
            stream.read_exact(&mut b).await?;
            IpAddr::V6(Ipv6Addr::from(b))
        }
        3 => {
            let size = stream.read_u8().await? as usize;
            ensure!(size > 0, "Пустой адрес SOCKS5");
            let mut b = vec![0; size];
            stream.read_exact(&mut b).await?;
            let hostname = String::from_utf8(b).context("Некорректный адрес relay")?;
            let port = stream.read_u16().await?;
            let address = tokio::net::lookup_host((hostname, port))
                .await?
                .next()
                .context("Адрес relay не найден")?;
            return Ok((stream, address));
        }
        _ => bail!("Неизвестный тип адреса SOCKS5"),
    };
    let port = stream.read_u16().await?;
    let ip = if ip.is_unspecified() {
        stream.peer_addr()?.ip()
    } else {
        ip
    };
    Ok((stream, SocketAddr::new(ip, port)))
}

pub async fn connect(proxy: &Proxy, target: SocketAddr) -> Result<TcpStream> {
    timeout(TIMEOUT, command(proxy, 1, target))
        .await
        .context("Таймаут SOCKS5 CONNECT")?
        .map(|(stream, _)| stream)
}

pub struct UdpAssociation {
    pub control: TcpStream,
    pub socket: UdpSocket,
}

pub async fn associate(proxy: &Proxy) -> Result<UdpAssociation> {
    timeout(TIMEOUT, async {
        // Bind before the handshake so the relay can associate our real source port.
        let mut control = negotiate(proxy).await?;
        let bind = if control.local_addr()?.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        let mut request = vec![5, 3, 0];
        encode_address(socket.local_addr()?, &mut request);
        control.write_all(&request).await?;
        let mut head = [0; 4];
        control.read_exact(&mut head).await?;
        ensure!(
            head[0] == 5 && head[1] == 0 && head[2] == 0,
            "SOCKS5-сервер не поддерживает UDP ASSOCIATE или отклонил запрос"
        );
        let relay_ip = match head[3] {
            1 => {
                let mut b = [0; 4];
                control.read_exact(&mut b).await?;
                IpAddr::V4(b.into())
            }
            4 => {
                let mut b = [0; 16];
                control.read_exact(&mut b).await?;
                IpAddr::V6(b.into())
            }
            3 => {
                let len = control.read_u8().await?;
                let mut b = vec![0; len as usize];
                control.read_exact(&mut b).await?;
                let host = String::from_utf8(b)?;
                let port = control.read_u16().await?;
                let relay = tokio::net::lookup_host((host, port))
                    .await?
                    .next()
                    .context("Не найден UDP relay")?;
                socket.connect(relay).await?;
                return Ok(UdpAssociation { control, socket });
            }
            _ => bail!("Некорректный UDP relay"),
        };
        let relay_port = control.read_u16().await?;
        ensure!(relay_port != 0, "Сервер вернул нулевой порт UDP relay");
        let relay_ip = if relay_ip.is_unspecified() {
            control.peer_addr()?.ip()
        } else {
            relay_ip
        };
        socket
            .connect(SocketAddr::new(relay_ip, relay_port))
            .await?;
        Ok(UdpAssociation { control, socket })
    })
    .await
    .context("Таймаут SOCKS5 UDP ASSOCIATE")?
}

pub fn udp_payload(bytes: &[u8]) -> Result<(SocketAddr, &[u8])> {
    ensure!(
        bytes.len() >= 4 && bytes[..3] == [0, 0, 0],
        "Некорректная или фрагментированная SOCKS5 UDP-датаграмма"
    );
    let (ip, offset) = match bytes[3] {
        1 if bytes.len() >= 10 => (
            IpAddr::V4(Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7])),
            8,
        ),
        4 if bytes.len() >= 22 => (
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[4..20])?)),
            20,
        ),
        _ => bail!("Неподдерживаемый адрес UDP-ответа SOCKS5"),
    };
    Ok((
        SocketAddr::new(ip, u16::from_be_bytes([bytes[offset], bytes[offset + 1]])),
        &bytes[offset + 2..],
    ))
}

pub async fn probe(proxy: &Proxy) -> Result<(u128, bool)> {
    let start = Instant::now();
    let stream = timeout(TIMEOUT, negotiate(proxy))
        .await
        .context("Таймаут SOCKS5")??;
    let latency = start.elapsed().as_millis();
    drop(stream);
    let udp = associate(proxy).await.is_ok();
    Ok((latency, udp))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn udp_roundtrip_v4_v6() {
        for address in ["1.2.3.4:443", "[2001:db8::1]:53"] {
            let address: SocketAddr = address.parse().unwrap();
            let mut b = vec![0, 0, 0];
            encode_address(address, &mut b);
            b.extend_from_slice(b"hello");
            let (a, p) = udp_payload(&b).unwrap();
            assert_eq!(a, address);
            assert_eq!(p, b"hello");
        }
    }
    #[test]
    fn rejects_fragments_and_truncation() {
        for b in [
            &[0, 0, 1, 1, 1, 2, 3, 4, 0, 53][..],
            &[0, 0, 0, 4, 1][..],
            &[],
        ] {
            assert!(udp_payload(b).is_err());
        }
    }
}
