//! Independent TLS peer controls for idle outbound worker retirement.
use super::*;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

#[allow(clippy::result_large_err)]
async fn run_peer(
    listener: tokio::net::TcpListener,
    tls: tokio_rustls::TlsAcceptor,
    mut commands: mpsc::Receiver<u8>,
    events: mpsc::Sender<()>,
) {
    let (tcp, _) = listener.accept().await.unwrap();
    let tls = tls.accept(tcp).await.unwrap();
    let mut ws = tokio_tungstenite::accept_hdr_async(
        tls,
        |_: &tokio_tungstenite::tungstenite::handshake::server::Request,
         mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
            response.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                crate::sc_frame::BACNET_SC_DIRECT_SUBPROTOCOL
                    .parse()
                    .unwrap(),
            );
            Ok(response)
        },
    )
    .await
    .unwrap();
    let request = ws.next().await.unwrap().unwrap().into_data();
    let request = decode_sc_message(&request).unwrap();
    let mut payload = Vec::new();
    payload.extend_from_slice(&REMOTE);
    payload.extend_from_slice(&[2; 16]);
    payload.extend_from_slice(&1476u16.to_be_bytes());
    payload.extend_from_slice(&1476u16.to_be_bytes());
    let mut message = ScMessage {
        function: ScFunction::ConnectAccept,
        message_id: request.message_id,
        originating_vmac: None,
        destination_vmac: None,
        dest_options: Vec::new(),
        data_options: Vec::new(),
        payload: bytes::Bytes::from(payload),
    };
    let mut wire = BytesMut::new();
    encode_sc_message(&mut wire, &message);
    ws.send(Message::Binary(wire.to_vec().into()))
        .await
        .unwrap();
    let npdu = ws.next().await.unwrap().unwrap().into_data();
    assert_eq!(
        decode_sc_message(&npdu).unwrap().function,
        ScFunction::EncapsulatedNpdu
    );
    events.send(()).await.unwrap();
    while let Some(command) = commands.recv().await {
        if command == 0 {
            ws.send(Message::Close(None)).await.unwrap();
            return;
        }
        if command == 1 {
            // The following control reply is a wire-order barrier: application
            // NPDUs read on this socket must not be admitted by this repair.
            message.function = ScFunction::EncapsulatedNpdu;
            message.payload = bytes::Bytes::from_static(NPDU);
            wire.clear();
            encode_sc_message(&mut wire, &message);
            ws.send(Message::Binary(wire.to_vec().into()))
                .await
                .unwrap();
        }
        message.function = ScFunction::DisconnectRequest;
        message.message_id = 0x3456;
        message.payload = if command == 1 {
            bytes::Bytes::from_static(&[0xaa])
        } else {
            bytes::Bytes::new()
        };
        wire.clear();
        encode_sc_message(&mut wire, &message);
        ws.send(Message::Binary(wire.to_vec().into()))
            .await
            .unwrap();
        let reply = tokio::time::timeout(WAIT, ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data();
        let reply = decode_sc_message(&reply).unwrap();
        assert_eq!(reply.message_id, message.message_id);
        assert_eq!(reply.originating_vmac, None);
        assert_eq!(reply.destination_vmac, None);
        assert!(reply.dest_options.is_empty() && reply.data_options.is_empty());
        if command == 1 {
            assert_eq!(reply.function, ScFunction::Result);
            let mut expected = vec![ScFunction::DisconnectRequest.to_raw(), 1, 0];
            expected.extend_from_slice(&ErrorClass::COMMUNICATION.to_raw().to_be_bytes());
            expected.extend_from_slice(&ErrorCode::INCONSISTENT_PARAMETERS.to_raw().to_be_bytes());
            assert_eq!(reply.payload.as_ref(), expected);
            events.send(()).await.unwrap();
        } else {
            assert_eq!(reply.function, ScFunction::DisconnectAck);
            assert!(reply.payload.is_empty());
            events.send(()).await.unwrap();
            // The client must close, with no additional NPDU or Disconnect request.
            let next = tokio::time::timeout(WAIT, ws.next()).await.unwrap();
            assert!(!matches!(next, Some(Ok(Message::Binary(_)))));
            return;
        }
    }
}

#[tokio::test]
async fn idle_outbound_close_and_disconnect_release_identity_with_exact_ack() {
    for close in [true, false] {
        let mut f = Fixture::new(1).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        f.uri = format!(
            "wss://localhost:{}/.bacnet/sc",
            listener.local_addr().unwrap().port()
        );
        let (commands, command_rx) = mpsc::channel(1);
        let (events, mut event_rx) = mpsc::channel(1);
        let peer = tokio::spawn(run_peer(listener, f.ca.acceptor(), command_rx, events));
        f.send().await.unwrap();
        event_rx.recv().await.unwrap();
        let old = f.direct.pooled_get(&REMOTE, Instant::now()).unwrap();
        if !close {
            commands.send(1).await.unwrap();
            tokio::time::timeout(WAIT, event_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(
                f.local_rx.try_recv().is_err(),
                "no outbound application NPDU admission"
            );
            assert!(
                old.member.is_current(),
                "malformed Disconnect must preserve membership"
            );
        }
        commands.send(if close { 0 } else { 2 }).await.unwrap();
        tokio::time::timeout(WAIT, peer).await.unwrap().unwrap();
        tokio::time::timeout(WAIT, async {
            while old.member.is_current()
                || f.direct.physical.available_permits() != DIRECT_POOL_MAX_ENTRIES * 2
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let (new, accept) = claim(&f.local, &f.ca, REMOTE, [4; 16]).await;
        assert_eq!(accept.function, ScFunction::ConnectAccept);
        old.member.retire();
        send_accepted(&new, REMOTE).await;
        receive(&mut f.local_rx, REMOTE).await;
        f.stop().await;
    }
}
