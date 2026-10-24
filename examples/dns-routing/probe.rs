//! Experimental deferred DNS routing, with owned helpers and loopback mock servers.
//! Does NOT open WinDivert, modify adapters, flush caches, or touch game processes.
#[cfg(windows)]
mod support;

#[cfg(windows)]
#[tokio::main(worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    support::run().await
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This probe requires Windows 11.");
    std::process::exit(1);
}
