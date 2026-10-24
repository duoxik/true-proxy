//! Local mock endpoints only: these tests do not open WinDivert or alter routing.
use anyhow::Result;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{Duration, timeout},
};
use true_proxy::{config::Proxy, socks};

fn proxy(address: SocketAddr) -> Proxy {
    Proxy {
        id: "test".into(),
        name: "Local mock".into(),
        host: address.ip().to_string(),
        port: address.port(),
        username: String::new(),
        protected_password: None,
    }
}

async fn greeting(stream: &mut TcpStream) -> Result<()> {
    let mut b = [0; 3];
    stream.read_exact(&mut b).await?;
    assert_eq!(b, [5, 1, 0]);
    stream.write_all(&[5, 0]).await?;
    Ok(())
}
async fn request(stream: &mut TcpStream, command: u8, target: SocketAddr) -> Result<()> {
    let mut expected = vec![5, command, 0];
    socks::encode_address(target, &mut expected);
    let mut got = vec![0; expected.len()];
    stream.read_exact(&mut got).await?;
    assert_eq!(got, expected);
    Ok(())
}

#[tokio::test]
async fn tcp_connect_handshake_and_real_payload() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let p = proxy(listener.local_addr()?);
    let target = "203.0.113.7:443".parse()?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        greeting(&mut stream).await?;
        request(&mut stream, 1, target).await?;
        stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").await?;
        Ok::<_, anyhow::Error>(())
    });
    let mut stream = socks::connect(&p, target).await?;
    stream.write_all(b"ping").await?;
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).await?;
    assert_eq!(&reply, b"pong");
    server.await??;
    Ok(())
}

#[tokio::test]
async fn supports_ipv6_destination() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let p = proxy(listener.local_addr()?);
    let target = "[2001:db8::1]:443".parse()?;
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await?;
        greeting(&mut s).await?;
        request(&mut s, 1, target).await?;
        s.write_all(&[
            5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
        ])
        .await?;
        Ok::<_, anyhow::Error>(())
    });
    socks::connect(&p, target).await?;
    server.await??;
    Ok(())
}

#[tokio::test]
async fn socks_rejection_does_not_connect_to_destination() -> Result<()> {
    let destination = TcpListener::bind("127.0.0.1:0").await?;
    let target = destination.local_addr()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let p = proxy(listener.local_addr()?);
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await?;
        greeting(&mut s).await?;
        request(&mut s, 1, target).await?;
        s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        Ok::<_, anyhow::Error>(())
    });
    assert!(socks::connect(&p, target).await.is_err());
    assert!(
        timeout(Duration::from_millis(100), destination.accept())
            .await
            .is_err()
    );
    server.await??;
    Ok(())
}

#[tokio::test]
async fn rejects_method_downgrade() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let p = proxy(listener.local_addr()?);
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await?;
        let mut b = [0; 3];
        s.read_exact(&mut b).await?;
        s.write_all(&[5, 2]).await?;
        Ok::<_, anyhow::Error>(())
    });
    assert!(
        socks::connect(&p, "203.0.113.7:443".parse()?)
            .await
            .is_err()
    );
    server.await??;
    Ok(())
}

#[tokio::test]
async fn dns_is_framed_over_tcp_through_socks() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let p = proxy(listener.local_addr()?);
    let query =
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await?;
        greeting(&mut s).await?;
        request(&mut s, 1, "1.1.1.1:53".parse()?).await?;
        s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let len = s.read_u16().await?;
        assert_eq!(len as usize, query.len());
        let mut q = vec![0; len as usize];
        s.read_exact(&mut q).await?;
        assert_eq!(q, query);
        q[2] = 0x81;
        q[3] = 0x80;
        s.write_u16(q.len() as u16).await?;
        s.write_all(&q).await?;
        Ok::<_, anyhow::Error>(())
    });
    let response = true_proxy::dns::exchange(&p, "1.1.1.1".parse()?, query).await?;
    assert_eq!(&response[..2], &query[..2]);
    assert_eq!(true_proxy::dns::questions(&response)?, vec!["example.com"]);
    server.await??;
    Ok(())
}

#[tokio::test]
async fn mismatched_dns_response_is_rejected() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let p = proxy(listener.local_addr()?);
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await?;
        greeting(&mut s).await?;
        request(&mut s, 1, "1.1.1.1:53".parse()?).await?;
        s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let len = s.read_u16().await?;
        let mut q = vec![0; len as usize];
        s.read_exact(&mut q).await?;
        q[0] ^= 1;
        q[2] |= 0x80;
        s.write_u16(q.len() as u16).await?;
        s.write_all(&q).await?;
        Ok::<_, anyhow::Error>(())
    });
    let query = b"\x12\x34\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    assert!(
        true_proxy::dns::exchange(&p, "1.1.1.1".parse()?, query)
            .await
            .is_err()
    );
    server.await??;
    Ok(())
}

#[tokio::test]
async fn udp_associate_and_datagram_exchange() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let p = proxy(listener.local_addr()?);
    let relay = UdpSocket::bind("127.0.0.1:0").await?;
    let relay_addr = relay.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut control, _) = listener.accept().await?;
        greeting(&mut control).await?;
        let mut b = [0; 10];
        control.read_exact(&mut b).await?;
        assert_eq!(&b[..4], &[5, 3, 0, 1]);
        assert_ne!(&b[8..10], &[0, 0]);
        let mut response = vec![5, 0, 0];
        socks::encode_address(relay_addr, &mut response);
        control.write_all(&response).await?;
        let mut packet = [0; 128];
        let (len, peer) = relay.recv_from(&mut packet).await?;
        let (target, data) = socks::udp_payload(&packet[..len])?;
        assert_eq!(target, "203.0.113.7:443".parse()?);
        assert_eq!(data, b"ping");
        let mut reply = vec![0, 0, 0];
        socks::encode_address(target, &mut reply);
        reply.extend_from_slice(b"pong");
        relay.send_to(&reply, peer).await?;
        let mut end = [0; 1];
        let _ = control.read(&mut end).await;
        Ok::<_, anyhow::Error>(())
    });
    let association = socks::associate(&p).await?;
    let mut packet = vec![0, 0, 0];
    socks::encode_address("203.0.113.7:443".parse()?, &mut packet);
    packet.extend_from_slice(b"ping");
    association.socket.send(&packet).await?;
    let mut bytes = [0; 128];
    let len = timeout(Duration::from_secs(2), association.socket.recv(&mut bytes)).await??;
    assert_eq!(socks::udp_payload(&bytes[..len])?.1, b"pong");
    drop(association);
    server.await??;
    Ok(())
}

#[cfg(windows)]
#[tokio::test]
async fn dpapi_password_and_authenticated_handshake() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let mut p = proxy(listener.local_addr()?);
    p.username = "user".into();
    p.protected_password = Some(true_proxy::platform::protect("pass")?);
    assert!(!serde_json::to_string(&p)?.contains("\"pass\""));
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await?;
        let mut method = [0; 3];
        s.read_exact(&mut method).await?;
        assert_eq!(method, [5, 1, 2]);
        s.write_all(&[5, 2]).await?;
        let mut auth = [0; 11];
        s.read_exact(&mut auth).await?;
        assert_eq!(&auth, b"\x01\x04user\x04pass");
        s.write_all(&[1, 0]).await?;
        request(&mut s, 1, "203.0.113.7:443".parse()?).await?;
        s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        Ok::<_, anyhow::Error>(())
    });
    socks::connect(&p, "203.0.113.7:443".parse()?).await?;
    server.await??;
    Ok(())
}

#[cfg(windows)]
#[test]
fn identifies_owner_of_tcp_and_udp_sockets_without_interception() -> Result<()> {
    use std::net::{TcpListener as Listener, TcpStream as Stream, UdpSocket as Udp};
    use true_proxy::{config::Protocol, packet::FlowKey, platform::windows::process};
    for (bind, target) in [("127.0.0.1:0", "127.0.0.1:9"), ("[::1]:0", "[::1]:9")] {
        let listener = Listener::bind(bind)?;
        let stream = Stream::connect(listener.local_addr()?)?;
        let _accepted = listener.accept()?;
        let owner = process::identify(
            FlowKey {
                source: stream.local_addr()?,
                destination: stream.peer_addr()?,
            },
            Protocol::Tcp,
        )?;
        assert_eq!(owner.pid, std::process::id());
        let socket = Udp::bind(bind)?;
        socket.connect(target)?;
        let owner = process::identify(
            FlowKey {
                source: socket.local_addr()?,
                destination: socket.peer_addr()?,
            },
            Protocol::Udp,
        )?;
        assert_eq!(owner.pid, std::process::id());
    }
    Ok(())
}
