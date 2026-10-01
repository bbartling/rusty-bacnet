//! Closing a connection after this side refused its TLS handshake.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

/// The longest a refused peer gets to read the alert before the socket closes.
const ALERT_LINGER: Duration = Duration::from_millis(500);

/// The most this side reads and discards from a refused peer. What a client
/// legitimately sends after its handshake flight is one HTTP upgrade request,
/// well under 2 KiB, so 64 KiB leaves ample room while an unauthenticated peer
/// can't keep a handshake slot reading at line rate for the whole linger.
const DRAIN_LIMIT: usize = 64 * 1024;

/// Close a TCP connection whose TLS handshake this side refused, so the peer
/// can read the alert that says why. Returns how many bytes were discarded.
///
/// rustls has already written the alert. Dropping the socket while records the
/// peer sent after its handshake flight (a TLS 1.3 client sends its HTTP
/// upgrade request straight away) are still unread makes the OS reset the
/// connection instead of closing it, and a Windows peer throws away unread
/// data, the alert included, when the reset arrives: it saw only "connection
/// reset" (#950). So send FIN after the alert, then read and discard what the
/// peer still sends until it closes. Stop after [`DRAIN_LIMIT`] bytes, after
/// [`ALERT_LINGER`], or at `deadline` (the handshake's own), whichever comes
/// first, and drop the socket.
pub(crate) async fn close_after_alert(mut tcp: TcpStream, deadline: Instant) -> usize {
    let deadline = deadline.min(Instant::now() + ALERT_LINGER);
    let mut discarded = 0;
    let _ = tokio::time::timeout_at(deadline, async {
        if tcp.shutdown().await.is_err() {
            return;
        }
        let mut buf = vec![0u8; 8 * 1024];
        while discarded < DRAIN_LIMIT {
            match tcp.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => discarded += n,
            }
        }
    })
    .await;
    discarded
}

#[cfg(test)]
#[path = "tls_reject_tests.rs"]
mod tests;
