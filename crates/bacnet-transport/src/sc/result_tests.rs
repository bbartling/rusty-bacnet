use super::*;

async fn hub_accept(ws_hub: &LoopbackWebSocket, hub_vmac: Vmac) {
    let data = ws_hub.recv().await.unwrap();
    let req = decode_sc_message(&data).unwrap();
    assert_eq!(req.function, ScFunction::ConnectRequest);

    let mut accept_payload = Vec::with_capacity(26);
    accept_payload.extend_from_slice(&hub_vmac);
    accept_payload.extend_from_slice(&[0u8; 16]);
    accept_payload.extend_from_slice(&1476u16.to_be_bytes());
    accept_payload.extend_from_slice(&1476u16.to_be_bytes());

    let accept = ScMessage {
        function: ScFunction::ConnectAccept,
        message_id: req.message_id,
        originating_vmac: None,
        destination_vmac: None,
        dest_options: Vec::new(),
        data_options: Vec::new(),
        payload: Bytes::from(accept_payload),
    };
    send_message(ws_hub, &accept).await;
}

fn bvlc_result_nak(message_id: u16) -> ScMessage {
    ScMessage {
        function: ScFunction::Result,
        message_id,
        originating_vmac: None,
        destination_vmac: None,
        dest_options: Vec::new(),
        data_options: Vec::new(),
        payload: Bytes::from_static(&[0x06, 0x01, 0x00, 0x00, 0x07, 0x01, 0x17]),
    }
}

async fn send_message(ws: &LoopbackWebSocket, msg: &ScMessage) {
    let mut buf = BytesMut::new();
    encode_sc_message(&mut buf, msg);
    ws.send(&buf).await.unwrap();
}

async fn wait_until_disconnected(conn: &Arc<Mutex<ScConnection>>) {
    for _ in 0..20 {
        if conn.lock().await.state == ScConnectionState::Disconnected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("connection did not transition to Disconnected");
}

#[test]
fn bvlc_result_nak_disconnects() {
    let mut conn = ScConnection::new([0x01; 6], [0u8; 16]);
    conn.state = ScConnectionState::Connected;
    let msg = ScMessage {
        function: ScFunction::Result,
        message_id: 1,
        originating_vmac: Some([0x10; 6]),
        destination_vmac: Some([0x01; 6]),
        dest_options: Vec::new(),
        data_options: Vec::new(),
        payload: Bytes::from_static(&[0x06, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01]),
    };
    let result = conn.handle_received(&msg);
    assert!(result.is_none());
    assert_eq!(conn.state, ScConnectionState::Disconnected);
}

#[test]
fn bvlc_result_success_no_disconnect() {
    let mut conn = ScConnection::new([0x01; 6], [0u8; 16]);
    conn.state = ScConnectionState::Connected;
    let msg = ScMessage {
        function: ScFunction::Result,
        message_id: 1,
        originating_vmac: Some([0x10; 6]),
        destination_vmac: Some([0x01; 6]),
        dest_options: Vec::new(),
        data_options: Vec::new(),
        payload: Bytes::from_static(&[0x0C, 0x00]),
    };
    let result = conn.handle_received(&msg);
    assert!(result.is_none());
    assert_eq!(conn.state, ScConnectionState::Connected);
}

#[test]
fn bvlc_result_ack_with_payload_no_disconnect() {
    let mut conn = ScConnection::new([0x01; 6], [0u8; 16]);
    conn.state = ScConnectionState::Connected;
    let msg = ScMessage {
        function: ScFunction::Result,
        message_id: 1,
        originating_vmac: None,
        destination_vmac: None,
        dest_options: Vec::new(),
        data_options: Vec::new(),
        payload: Bytes::from_static(&[0x0C, 0x00]),
    };
    let result = conn.handle_received(&msg);
    assert!(result.is_none());
    assert_eq!(conn.state, ScConnectionState::Connected);
}

#[test]
fn malformed_bvlc_result_disconnects() {
    let mut conn = ScConnection::new([0x01; 6], [0u8; 16]);
    conn.state = ScConnectionState::Connected;
    let msg = ScMessage {
        function: ScFunction::Result,
        message_id: 1,
        originating_vmac: Some([0x10; 6]),
        destination_vmac: Some([0x01; 6]),
        dest_options: Vec::new(),
        data_options: Vec::new(),
        payload: Bytes::new(),
    };
    let result = conn.handle_received(&msg);
    assert!(result.is_none());
    assert_eq!(conn.state, ScConnectionState::Disconnected);
}

#[tokio::test]
async fn sc_connect_result_nak_fails_without_timeout() {
    let (ws_client, ws_server) = LoopbackWebSocket::pair();
    let mut transport = ScTransport::new(ws_client, [0x01; 6]).with_connect_timeout_ms(5000);

    let hub_task = tokio::spawn(async move {
        let data = ws_server.recv().await.unwrap();
        let req = decode_sc_message(&data).unwrap();
        assert_eq!(req.function, ScFunction::ConnectRequest);
        send_message(&ws_server, &bvlc_result_nak(req.message_id)).await;
    });

    let started = Instant::now();
    let result = transport.start().await;
    assert!(result.is_err());
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "BVLC-Result NAK should fail connect before timeout"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("BVLC-Result NAK"), "{err_msg}");

    let conn = transport.connection().unwrap();
    assert_eq!(conn.lock().await.state, ScConnectionState::Disconnected);
    hub_task.await.unwrap();
}

#[tokio::test]
async fn sc_result_nak_closes_receive_loop_before_heartbeat() {
    let (ws_client, ws_hub) = LoopbackWebSocket::pair();
    let client_vmac = [0x01; 6];
    let hub_vmac = [0x10; 6];

    let mut transport = ScTransport::new(ws_client, client_vmac)
        .with_heartbeat_interval_ms(500)
        .with_heartbeat_timeout_ms(5000);

    let hub_task = tokio::spawn(async move {
        hub_accept(&ws_hub, hub_vmac).await;
        ws_hub
    });

    let _rx = transport.start().await.unwrap();
    let ws_hub = hub_task.await.unwrap();
    let conn = transport.connection().unwrap().clone();

    send_message(&ws_hub, &bvlc_result_nak(1)).await;
    wait_until_disconnected(&conn).await;

    assert!(
        tokio::time::timeout(Duration::from_millis(200), ws_hub.recv())
            .await
            .is_err(),
        "receive loop should close before sending another heartbeat"
    );

    transport.stop().await.unwrap();
}

#[tokio::test]
async fn malformed_wire_bvlc_result_closes_receive_loop() {
    let (ws_client, ws_hub) = LoopbackWebSocket::pair();
    let client_vmac = [0x01; 6];
    let hub_vmac = [0x10; 6];

    let mut transport = ScTransport::new(ws_client, client_vmac)
        .with_heartbeat_interval_ms(500)
        .with_heartbeat_timeout_ms(5000);

    let hub_task = tokio::spawn(async move {
        hub_accept(&ws_hub, hub_vmac).await;
        ws_hub
    });

    let _rx = transport.start().await.unwrap();
    let ws_hub = hub_task.await.unwrap();
    let conn = transport.connection().unwrap().clone();

    ws_hub.send(&[ScFunction::Result.to_raw()]).await.unwrap();
    wait_until_disconnected(&conn).await;

    assert!(
        tokio::time::timeout(Duration::from_millis(200), ws_hub.recv())
            .await
            .is_err(),
        "malformed Result should close the receive loop without a Result response"
    );

    transport.stop().await.unwrap();
}
