//! Owned probe process only. No foreign-process access, injection, or interception.
#[cfg(windows)]
mod native_dns;

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use std::{
        io::{Read, Write},
        net::{Ipv4Addr, Shutdown, TcpStream, ToSocketAddrs},
        time::Duration,
    };
    let args = std::env::args().collect::<Vec<_>>();
    ensure!(args.len() == 5, "Expected: DNS-server name port payload");
    let server: Ipv4Addr = args[1].parse()?;
    let name = args[2].trim_end_matches('.');
    ensure!(
        server.is_loopback() && name.ends_with(".invalid"),
        "Probe accepts loopback DNS and .invalid names only"
    );
    let port: u16 = args[3].parse()?;
    let _scope = native_dns::Scope::new(server)?;
    // This invokes the ordinary Windows resolver in THIS executable, not a custom
    // DNS client. The broker must recover the process identity after resolution.
    let target = (format!("{name}."), port)
        .to_socket_addrs()?
        .find(|address| address.is_ipv4())
        .context("No IPv4 response")?;
    ensure!(
        target.ip().is_loopback(),
        "Probe must never connect outside loopback"
    );
    let mut stream = TcpStream::connect_timeout(&target, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(args[4].as_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    let mut reply = String::new();
    stream.take(1024).read_to_string(&mut reply)?;
    println!(
        "{}",
        serde_json::json!({"pid": std::process::id(), "fake_ip": target.ip(), "reply": reply})
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This probe requires Windows 11 and does not run on other platforms.");
    std::process::exit(1);
}
