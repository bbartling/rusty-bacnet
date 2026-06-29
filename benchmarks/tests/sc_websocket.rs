//! Integration tests for BACnet/SC WebSocket layer behavior.

use std::time::Duration;

use bacnet_benchmarks::sc_helpers::{
    generate_test_certs, make_client_tls_config, start_sc_hub, CertMaterial,
};
use bacnet_transport::sc_frame::{
    decode_sc_message, encode_sc_message, ScFunction, ScMessage, ScOption, Vmac,
    BACNET_SC_HUB_SUBPROTOCOL, BROADCAST_VMAC,
};
use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::ClientRequestBuilder;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

type ClientWs = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[tokio::test]
async fn sc_websocket_hub_subprotocol_handshake_succeeds() {
    let certs = generate_test_certs();
    let (mut hub, url) = start_sc_hub(&certs, [0x10; 6]).await;

    let request = ClientRequestBuilder::new(url.parse().unwrap())
        .with_sub_protocol(BACNET_SC_HUB_SUBPROTOCOL);
    let connector = tokio_tungstenite::Connector::Rustls(make_client_tls_config(&certs));
    let (_ws, response) =
        tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector))
            .await
            .unwrap();

    let selected = response
        .headers()
        .get("Sec-WebSocket-Protocol")
        .and_then(|value| value.to_str().ok());
    assert_eq!(selected, Some(BACNET_SC_HUB_SUBPROTOCOL));

    hub.stop().await;
}

#[tokio::test]
async fn sc_websocket_hub_rejects_missing_or_wrong_subprotocol() {
    let certs = generate_test_certs();
    let (mut hub, url) = start_sc_hub(&certs, [0x20; 6]).await;

    let missing_request = ClientRequestBuilder::new(url.parse().unwrap());
    let missing_connector = tokio_tungstenite::Connector::Rustls(make_client_tls_config(&certs));
    let missing_result = tokio_tungstenite::connect_async_tls_with_config(
        missing_request,
        None,
        false,
        Some(missing_connector),
    )
    .await;
    assert!(missing_result.is_err());

    let wrong_request =
        ClientRequestBuilder::new(url.parse().unwrap()).with_sub_protocol("dc.bsc.bacnet.org");
    let wrong_connector = tokio_tungstenite::Connector::Rustls(make_client_tls_config(&certs));
    let wrong_result = tokio_tungstenite::connect_async_tls_with_config(
        wrong_request,
        None,
        false,
        Some(wrong_connector),
    )
    .await;
    assert!(wrong_result.is_err());

    hub.stop().await;
}

#[tokio::test]
async fn sc_websocket_text_frame_closes_with_unsupported_data() {
    let certs = generate_test_certs();
    let (mut hub, url) = start_sc_hub(&certs, [0x30; 6]).await;

    let request = ClientRequestBuilder::new(url.parse().unwrap())
        .with_sub_protocol(BACNET_SC_HUB_SUBPROTOCOL);
    let connector = tokio_tungstenite::Connector::Rustls(make_client_tls_config(&certs));
    let (mut ws, _response) =
        tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector))
            .await
            .unwrap();

    ws.send(Message::Text("not a BVLC-SC binary frame".into()))
        .await
        .unwrap();
    let message = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("hub should close promptly after a text frame")
        .expect("hub should send a close frame")
        .expect("close frame should decode");

    match message {
        Message::Close(Some(frame)) => assert_eq!(frame.code, CloseCode::Unsupported),
        other => panic!("expected unsupported-data close frame, got {other:?}"),
    }

    hub.stop().await;
}

#[tokio::test]
async fn sc_websocket_hub_relays_unicast_unknown_and_broadcast_with_vmac_rules() {
    let certs = generate_test_certs();
    let (mut hub, url) = start_sc_hub(&certs, [0x10; 6]).await;

    let vmac_a = [0xA1; 6];
    let vmac_b = [0xB2; 6];
    let vmac_c = [0xC3; 6];

    let mut ws_a = connect_sc_client(&url, &certs, vmac_a).await;
    let mut ws_b = connect_sc_client(&url, &certs, vmac_b).await;
    let mut ws_c = connect_sc_client(&url, &certs, vmac_c).await;

    let unicast = ScMessage {
        function: ScFunction::EncapsulatedNpdu,
        message_id: 0x2001,
        originating_vmac: None,
        destination_vmac: Some(vmac_b),
        dest_options: vec![ScOption {
            option_type: 2,
            must_understand: false,
            data: vec![0xAA, 0xBB],
        }],
        data_options: vec![ScOption {
            option_type: 3,
            must_understand: true,
            data: Vec::new(),
        }],
        payload: Bytes::from_static(&[0x01, 0x20, 0x30]),
    };
    send_sc_message(&mut ws_a, &unicast).await;

    let relayed_unicast = recv_sc_message(&mut ws_b).await;
    assert_eq!(relayed_unicast.function, ScFunction::EncapsulatedNpdu);
    assert_eq!(relayed_unicast.message_id, unicast.message_id);
    assert_eq!(relayed_unicast.originating_vmac, Some(vmac_a));
    assert_eq!(relayed_unicast.destination_vmac, None);
    assert_eq!(relayed_unicast.dest_options, unicast.dest_options);
    assert_eq!(relayed_unicast.data_options, unicast.data_options);
    assert_eq!(relayed_unicast.payload, unicast.payload);
    assert_no_sc_message(&mut ws_a).await;
    assert_no_sc_message(&mut ws_c).await;

    let unknown_unicast = ScMessage {
        destination_vmac: Some([0xD4; 6]),
        message_id: 0x2002,
        ..unicast.clone()
    };
    send_sc_message(&mut ws_a, &unknown_unicast).await;
    assert_no_sc_message(&mut ws_a).await;
    assert_no_sc_message(&mut ws_b).await;
    assert_no_sc_message(&mut ws_c).await;

    let broadcast = ScMessage {
        message_id: 0x2003,
        destination_vmac: Some(BROADCAST_VMAC),
        payload: Bytes::from_static(&[0x01, 0x04, 0x05]),
        ..unicast
    };
    send_sc_message(&mut ws_a, &broadcast).await;

    let relayed_b = recv_sc_message(&mut ws_b).await;
    let relayed_c = recv_sc_message(&mut ws_c).await;
    for relayed in [relayed_b, relayed_c] {
        assert_eq!(relayed.function, ScFunction::EncapsulatedNpdu);
        assert_eq!(relayed.message_id, broadcast.message_id);
        assert_eq!(relayed.originating_vmac, Some(vmac_a));
        assert_eq!(relayed.destination_vmac, Some(BROADCAST_VMAC));
        assert_eq!(relayed.dest_options, broadcast.dest_options);
        assert_eq!(relayed.data_options, broadcast.data_options);
        assert_eq!(relayed.payload, broadcast.payload);
    }
    assert_no_sc_message(&mut ws_a).await;

    hub.stop().await;
}

async fn connect_sc_client(url: &str, certs: &CertMaterial, vmac: Vmac) -> ClientWs {
    let request = ClientRequestBuilder::new(url.parse().unwrap())
        .with_sub_protocol(BACNET_SC_HUB_SUBPROTOCOL);
    let connector = tokio_tungstenite::Connector::Rustls(make_client_tls_config(certs));
    let (mut ws, _response) =
        tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector))
            .await
            .unwrap();

    let mut payload = Vec::with_capacity(26);
    payload.extend_from_slice(&vmac);
    payload.extend_from_slice(&[vmac[0]; 16]);
    payload.extend_from_slice(&1476u16.to_be_bytes());
    payload.extend_from_slice(&1476u16.to_be_bytes());

    let request = ScMessage {
        function: ScFunction::ConnectRequest,
        message_id: 0x1000 | vmac[0] as u16,
        originating_vmac: None,
        destination_vmac: None,
        dest_options: Vec::new(),
        data_options: Vec::new(),
        payload: Bytes::from(payload),
    };
    send_sc_message(&mut ws, &request).await;

    let accept = recv_sc_message(&mut ws).await;
    assert_eq!(accept.function, ScFunction::ConnectAccept);
    assert_eq!(accept.message_id, request.message_id);
    assert_eq!(accept.originating_vmac, None);
    assert_eq!(accept.destination_vmac, None);
    assert_eq!(accept.payload.len(), 26);

    ws
}

async fn send_sc_message(ws: &mut ClientWs, msg: &ScMessage) {
    let mut buf = BytesMut::new();
    encode_sc_message(&mut buf, msg);
    ws.send(Message::Binary(buf.to_vec().into())).await.unwrap();
}

async fn recv_sc_message(ws: &mut ClientWs) -> ScMessage {
    let message = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("expected SC message before timeout")
        .expect("websocket should still be open")
        .expect("websocket frame should decode");

    match message {
        Message::Binary(data) => decode_sc_message(&data).unwrap(),
        other => panic!("expected SC binary message, got {other:?}"),
    }
}

async fn assert_no_sc_message(ws: &mut ClientWs) {
    let result = tokio::time::timeout(Duration::from_millis(200), ws.next()).await;
    assert!(result.is_err(), "unexpected WebSocket message: {result:?}");
}
