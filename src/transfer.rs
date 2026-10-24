//! Stream accounting is updated on writes, independently of UI refreshes.
use std::{
    io,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct Metered<'a, T> {
    inner: &'a mut T,
    written: &'a AtomicU64,
    additional: Option<&'a AtomicU64>,
}
impl<T: AsyncRead + Unpin> AsyncRead for Metered<'_, T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_read(cx, buffer)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Metered<'_, T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut *self.inner).poll_write(cx, buffer);
        if let Poll::Ready(Ok(size)) = result {
            self.written.fetch_add(size as u64, Ordering::Relaxed);
            if let Some(additional) = self.additional {
                additional.fetch_add(size as u64, Ordering::Relaxed);
            }
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

pub async fn relay<A: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin>(
    local: &mut A,
    remote: &mut B,
    upload: &AtomicU64,
    download: &AtomicU64,
) -> io::Result<()> {
    relay_inner(local, remote, upload, download, None).await
}

pub async fn relay_for_process<
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
>(
    local: &mut A,
    remote: &mut B,
    upload: &AtomicU64,
    download: &AtomicU64,
    process_upload: &AtomicU64,
    process_download: &AtomicU64,
) -> io::Result<()> {
    relay_inner(
        local,
        remote,
        upload,
        download,
        Some((process_upload, process_download)),
    )
    .await
}

async fn relay_inner<A: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin>(
    local: &mut A,
    remote: &mut B,
    upload: &AtomicU64,
    download: &AtomicU64,
    process: Option<(&AtomicU64, &AtomicU64)>,
) -> io::Result<()> {
    let mut local = Metered {
        inner: local,
        written: download,
        additional: process.map(|counters| counters.1),
    };
    let mut remote = Metered {
        inner: remote,
        written: upload,
        additional: process.map(|counters| counters.0),
    };
    tokio::io::copy_bidirectional_with_sizes(&mut local, &mut remote, 8192, 8192).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        time::{Duration, timeout},
    };
    #[tokio::test]
    async fn counts_live_traffic_and_preserves_half_close() -> io::Result<()> {
        let (mut client, mut local) = tokio::io::duplex(64);
        let (mut remote, mut server) = tokio::io::duplex(64);
        let stats = std::sync::Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
        let process_stats = std::sync::Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
        let worker_stats = stats.clone();
        let worker_process = process_stats.clone();
        let worker = tokio::spawn(async move {
            relay_for_process(
                &mut local,
                &mut remote,
                &worker_stats.0,
                &worker_stats.1,
                &worker_process.0,
                &worker_process.1,
            )
            .await
        });
        client.write_all(b"request").await?;
        client.shutdown().await?;
        let mut request = Vec::new();
        timeout(Duration::from_secs(1), server.read_to_end(&mut request)).await??;
        assert_eq!(request, b"request");
        assert_eq!(stats.0.load(Ordering::Relaxed), 7);
        assert_eq!(process_stats.0.load(Ordering::Relaxed), 7);
        server.write_all(b"response").await?;
        let mut response = [0; 8];
        timeout(Duration::from_secs(1), client.read_exact(&mut response)).await??;
        assert_eq!(&response, b"response");
        assert_eq!(stats.1.load(Ordering::Relaxed), 8);
        assert_eq!(process_stats.1.load(Ordering::Relaxed), 8);
        server.shutdown().await?;
        timeout(Duration::from_secs(1), worker).await???;
        Ok(())
    }
}
