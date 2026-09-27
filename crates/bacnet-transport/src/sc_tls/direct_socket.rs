//! Direct accepted-socket adapter, also used by deterministic write seams.
use futures_util::{SinkExt, StreamExt};

/// Minimal WebSocket surface used by the acceptor handshake and NPDU loop.
pub(super) trait DirectWs {
    type Read: DirectWsRead;
    async fn send_data(&mut self, data: &[u8]) -> Result<(), ()>;
    async fn send_close(&mut self) -> Result<(), ()>;
}

pub(super) trait DirectWsRead {
    async fn next_data(&mut self) -> Option<Result<Vec<u8>, String>>;
}

type TlsWsStream =
    tokio_tungstenite::WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>;

impl DirectWs
    for futures_util::stream::SplitSink<TlsWsStream, tokio_tungstenite::tungstenite::Message>
{
    type Read = futures_util::stream::SplitStream<TlsWsStream>;
    async fn send_data(&mut self, data: &[u8]) -> Result<(), ()> {
        self.send(tokio_tungstenite::tungstenite::Message::Binary(
            data.to_vec().into(),
        ))
        .await
        .map_err(|_| ())
    }
    async fn send_close(&mut self) -> Result<(), ()> {
        self.send(tokio_tungstenite::tungstenite::Message::Close(None))
            .await
            .map_err(|_| ())
    }
}

impl DirectWsRead for futures_util::stream::SplitStream<TlsWsStream> {
    async fn next_data(&mut self) -> Option<Result<Vec<u8>, String>> {
        loop {
            match self.next().await {
                Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(data))) => {
                    return Some(Ok(data.to_vec()));
                }
                Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) => return None,
                Some(Ok(
                    tokio_tungstenite::tungstenite::Message::Ping(_)
                    | tokio_tungstenite::tungstenite::Message::Pong(_),
                )) => continue,
                Some(Ok(_)) => return Some(Err("non-binary".into())),
                Some(Err(e)) => return Some(Err(e.to_string())),
                None => return None,
            }
        }
    }
}
