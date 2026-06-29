//! Integration tests for BACnet/SC WebSocket layer behavior.

use std::time::Duration;

use bacnet_benchmarks::sc_helpers::{generate_test_certs, make_client_tls_config, start_sc_hub};
use bacnet_transport::sc_frame::BACNET_SC_HUB_SUBPROTOCOL;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::ClientRequestBuilder;

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
