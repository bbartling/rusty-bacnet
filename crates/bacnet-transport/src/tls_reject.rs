//! Closing a connection after this side refused its TLS handshake.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

/// The longest a refused peer gets to read the alert before the socket closes.
const ALERT_LINGER: Duration = Duration::from_millis(500);

/// Close a TCP connection whose TLS handshake this side refused, so the peer
/// can read the alert that says why.
///
/// rustls has already written the alert. Dropping the socket while records the
/// peer sent after its handshake flight (a TLS 1.3 client sends its HTTP
/// upgrade request straight away) are still unread makes the OS reset the
/// connection instead of closing it, and a Windows peer throws away unread
/// data, the alert included, when the reset arrives: it saw only "connection
/// reset" (#950). So send FIN after the alert, then read and discard what the
/// peer still sends until it closes, for at most [`ALERT_LINGER`] and never
/// past `deadline`, the handshake's own deadline.
pub(crate) async fn close_after_alert(mut tcp: TcpStream, deadline: Instant) {
    let deadline = deadline.min(Instant::now() + ALERT_LINGER);
    let _ = tokio::time::timeout_at(deadline, async {
        if tcp.shutdown().await.is_err() {
            return;
        }
        let mut discard = [0u8; 1024];
        while matches!(tcp.read(&mut discard).await, Ok(n) if n > 0) {}
    })
    .await;
}
