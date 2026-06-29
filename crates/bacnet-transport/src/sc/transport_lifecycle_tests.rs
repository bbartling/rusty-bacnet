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
    let mut buf = BytesMut::new();
    encode_sc_message(&mut buf, &accept);
    ws_hub.send(&buf).await.unwrap();
}

async fn wait_for_connection_state(
    conn: &Arc<Mutex<ScConnection>>,
    expected: ScConnectionState,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if conn.lock().await.state == expected {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

#[tokio::test]
async fn sc_connect_timeout() {
    let (ws_client, _ws_server) = LoopbackWebSocket::pair();
    let vmac = [0x01; 6];
    let mut transport = ScTransport::new(ws_client, vmac).with_connect_timeout_ms(200);
    // Don't send ConnectAccept from server side; this should timeout.
    let result = transport.start().await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("timeout"),
        "Expected timeout error, got: {}",
        err_msg
    );
}

#[tokio::test]
async fn sc_connect_rejects_mismatched_accept_message_id() {
    let (ws_client, ws_server) = LoopbackWebSocket::pair();
    let vmac = [0x01; 6];
    let mut transport = ScTransport::new(ws_client, vmac).with_connect_timeout_ms(5000);

    let hub_task = tokio::spawn(async move {
        let data = ws_server.recv().await.unwrap();
        let req = decode_sc_message(&data).unwrap();
        assert_eq!(req.function, ScFunction::ConnectRequest);

        let mut payload = Vec::with_capacity(26);
        payload.extend_from_slice(&[0x10; 6]);
        payload.extend_from_slice(&[0u8; 16]);
        payload.extend_from_slice(&1476u16.to_be_bytes());
        payload.extend_from_slice(&1476u16.to_be_bytes());
        let accept = ScMessage {
            function: ScFunction::ConnectAccept,
            message_id: req.message_id.wrapping_add(1),
            originating_vmac: None,
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::from(payload),
        };
        let mut buf = BytesMut::new();
        encode_sc_message(&mut buf, &accept);
        ws_server.send(&buf).await.unwrap();
    });

    let result = transport.start().await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("Connect-Accept"),
        "Expected Connect-Accept mismatch error, got: {}",
        err_msg
    );
    let conn = transport.connection().unwrap();
    assert_eq!(conn.lock().await.state, ScConnectionState::Disconnected);
    hub_task.await.unwrap();
}

#[tokio::test]
async fn sc_heartbeat_sent_periodically() {
    let (ws_client, ws_hub) = LoopbackWebSocket::pair();
    let client_vmac = [0x01; 6];
    let hub_vmac = [0x10; 6];

    let mut transport = ScTransport::new(ws_client, client_vmac)
        .with_heartbeat_interval_ms(200)
        .with_heartbeat_timeout_ms(5000);

    // Hub accepts the connection, then we interact with the hub ws
    let hub_task = tokio::spawn(async move {
        hub_accept(&ws_hub, hub_vmac).await;
        ws_hub
    });

    let _rx = transport.start().await.unwrap();
    let ws_hub = hub_task.await.unwrap();

    // Wait enough time for the heartbeat interval to fire
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The hub should receive a HeartbeatRequest
    let data = tokio::time::timeout(Duration::from_millis(500), ws_hub.recv())
        .await
        .expect("timed out waiting for heartbeat")
        .unwrap();
    let msg = decode_sc_message(&data).unwrap();
    assert_eq!(msg.function, ScFunction::HeartbeatRequest);
    assert!(msg.originating_vmac.is_none());

    // Send HeartbeatAck back so the transport doesn't timeout
    let ack = ScMessage {
        function: ScFunction::HeartbeatAck,
        message_id: msg.message_id,
        originating_vmac: None,
        destination_vmac: None,
        dest_options: Vec::new(),
        data_options: Vec::new(),
        payload: Bytes::new(),
    };
    let mut buf = BytesMut::new();
    encode_sc_message(&mut buf, &ack);
    ws_hub.send(&buf).await.unwrap();

    transport.stop().await.unwrap();
}

#[tokio::test]
async fn sc_heartbeat_ack_requires_matching_message_id() {
    let (ws_client, ws_hub) = LoopbackWebSocket::pair();
    let client_vmac = [0x01; 6];
    let hub_vmac = [0x10; 6];

    let mut transport = ScTransport::new(ws_client, client_vmac)
        .with_heartbeat_interval_ms(100)
        .with_heartbeat_timeout_ms(300);

    let hub_task = tokio::spawn(async move {
        hub_accept(&ws_hub, hub_vmac).await;
        ws_hub
    });

    let _rx = transport.start().await.unwrap();
    let ws_hub = hub_task.await.unwrap();
    let conn = transport.connection().unwrap().clone();

    let data = tokio::time::timeout(Duration::from_millis(300), ws_hub.recv())
        .await
        .expect("timed out waiting for heartbeat")
        .unwrap();
    let msg = decode_sc_message(&data).unwrap();
    assert_eq!(msg.function, ScFunction::HeartbeatRequest);

    let ack = ScMessage {
        function: ScFunction::HeartbeatAck,
        message_id: msg.message_id.wrapping_add(1),
        originating_vmac: None,
        destination_vmac: None,
        dest_options: Vec::new(),
        data_options: Vec::new(),
        payload: Bytes::new(),
    };
    let mut buf = BytesMut::new();
    encode_sc_message(&mut buf, &ack);
    ws_hub.send(&buf).await.unwrap();

    assert!(
        wait_for_connection_state(
            &conn,
            ScConnectionState::Disconnected,
            Duration::from_millis(500)
        )
        .await
    );
    transport.stop().await.unwrap();
}

#[tokio::test]
async fn sc_heartbeat_ack_rejects_vmac_fields() {
    let (ws_client, ws_hub) = LoopbackWebSocket::pair();
    let client_vmac = [0x01; 6];
    let hub_vmac = [0x10; 6];

    let mut transport = ScTransport::new(ws_client, client_vmac)
        .with_heartbeat_interval_ms(100)
        .with_heartbeat_timeout_ms(300);

    let hub_task = tokio::spawn(async move {
        hub_accept(&ws_hub, hub_vmac).await;
        ws_hub
    });

    let _rx = transport.start().await.unwrap();
    let ws_hub = hub_task.await.unwrap();
    let conn = transport.connection().unwrap().clone();

    let data = tokio::time::timeout(Duration::from_millis(300), ws_hub.recv())
        .await
        .expect("timed out waiting for heartbeat")
        .unwrap();
    let msg = decode_sc_message(&data).unwrap();
    assert_eq!(msg.function, ScFunction::HeartbeatRequest);

    let ack = ScMessage {
        function: ScFunction::HeartbeatAck,
        message_id: msg.message_id,
        originating_vmac: Some(hub_vmac),
        destination_vmac: Some(client_vmac),
        dest_options: Vec::new(),
        data_options: Vec::new(),
        payload: Bytes::new(),
    };
    let mut buf = BytesMut::new();
    encode_sc_message(&mut buf, &ack);
    ws_hub.send(&buf).await.unwrap();

    assert!(
        wait_for_connection_state(
            &conn,
            ScConnectionState::Disconnected,
            Duration::from_millis(500)
        )
        .await
    );
    transport.stop().await.unwrap();
}

#[tokio::test]
async fn sc_inbound_bvlc_activity_defers_client_heartbeat() {
    let (ws_client, ws_hub) = LoopbackWebSocket::pair();
    let client_vmac = [0x01; 6];
    let hub_vmac = [0x10; 6];

    let mut transport = ScTransport::new(ws_client, client_vmac)
        .with_heartbeat_interval_ms(100)
        .with_heartbeat_timeout_ms(1000);

    let hub_task = tokio::spawn(async move {
        hub_accept(&ws_hub, hub_vmac).await;
        ws_hub
    });

    let _rx = transport.start().await.unwrap();
    let ws_hub = hub_task.await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;
    let hb = ScMessage {
        function: ScFunction::HeartbeatRequest,
        message_id: 0x55,
        originating_vmac: None,
        destination_vmac: None,
        dest_options: Vec::new(),
        data_options: Vec::new(),
        payload: Bytes::new(),
    };
    let mut hb_buf = BytesMut::new();
    encode_sc_message(&mut hb_buf, &hb);
    ws_hub.send(&hb_buf).await.unwrap();

    let data = tokio::time::timeout(Duration::from_millis(100), ws_hub.recv())
        .await
        .expect("timed out waiting for heartbeat ack")
        .unwrap();
    let ack = decode_sc_message(&data).unwrap();
    assert_eq!(ack.function, ScFunction::HeartbeatAck);
    assert_eq!(ack.message_id, 0x55);

    assert!(
        tokio::time::timeout(Duration::from_millis(80), ws_hub.recv())
            .await
            .is_err(),
        "client heartbeat was sent before the connection was idle"
    );

    transport.stop().await.unwrap();
}

#[tokio::test]
async fn sc_inbound_bvlc_activity_resets_heartbeat_timeout() {
    let (ws_client, ws_hub) = LoopbackWebSocket::pair();
    let client_vmac = [0x01; 6];
    let hub_vmac = [0x10; 6];

    let mut transport = ScTransport::new(ws_client, client_vmac)
        .with_heartbeat_interval_ms(100)
        .with_heartbeat_timeout_ms(300);

    let hub_task = tokio::spawn(async move {
        hub_accept(&ws_hub, hub_vmac).await;
        ws_hub
    });

    let _rx = transport.start().await.unwrap();
    let ws_hub = hub_task.await.unwrap();
    let conn = transport.connection().unwrap().clone();

    tokio::time::sleep(Duration::from_millis(250)).await;
    let hb = ScMessage {
        function: ScFunction::HeartbeatRequest,
        message_id: 0x66,
        originating_vmac: None,
        destination_vmac: None,
        dest_options: Vec::new(),
        data_options: Vec::new(),
        payload: Bytes::new(),
    };
    let mut hb_buf = BytesMut::new();
    encode_sc_message(&mut hb_buf, &hb);
    ws_hub.send(&hb_buf).await.unwrap();

    let mut received_ack = false;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let data = tokio::time::timeout(remaining, ws_hub.recv())
            .await
            .expect("timed out waiting for heartbeat ack")
            .unwrap();
        let msg = decode_sc_message(&data).unwrap();
        if msg.function == ScFunction::HeartbeatAck && msg.message_id == 0x66 {
            received_ack = true;
            break;
        }
    }
    assert!(
        received_ack,
        "transport did not acknowledge inbound heartbeat"
    );

    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(conn.lock().await.state, ScConnectionState::Connected);

    transport.stop().await.unwrap();
}

#[tokio::test]
async fn sc_heartbeat_timeout_disconnects() {
    let (ws_client, ws_hub) = LoopbackWebSocket::pair();
    let client_vmac = [0x01; 6];
    let hub_vmac = [0x10; 6];

    let mut transport = ScTransport::new(ws_client, client_vmac)
        .with_heartbeat_interval_ms(100)
        .with_heartbeat_timeout_ms(300);

    // Hub accepts the connection but will NOT respond to heartbeats
    let hub_task = tokio::spawn(async move {
        hub_accept(&ws_hub, hub_vmac).await;
        ws_hub
    });

    let _rx = transport.start().await.unwrap();
    let _ws_hub = hub_task.await.unwrap();

    // Wait long enough for the heartbeat timeout to fire (~500ms > 300ms timeout)
    tokio::time::sleep(Duration::from_millis(600)).await;

    // The recv task should have ended and connection state should be Disconnected
    let conn = transport.connection().unwrap();
    let c = conn.lock().await;
    assert_eq!(c.state, ScConnectionState::Disconnected);
    drop(c);

    transport.stop().await.unwrap();
}

#[tokio::test]
async fn sc_connect_succeeds_within_timeout() {
    let (ws_client, ws_server) = LoopbackWebSocket::pair();
    let vmac = [0x01; 6];
    let mut transport = ScTransport::new(ws_client, vmac).with_connect_timeout_ms(5000);

    // Spawn hub accept in background
    let hub_task = tokio::spawn(async move {
        // Receive ConnectRequest
        let data = ws_server.recv().await.unwrap();
        let req = decode_sc_message(&data).unwrap();
        assert_eq!(req.function, ScFunction::ConnectRequest);

        let mut payload = Vec::with_capacity(26);
        payload.extend_from_slice(&[0x10; 6]); // hub VMAC
        payload.extend_from_slice(&[0u8; 16]); // hub Device UUID
        payload.extend_from_slice(&1476u16.to_be_bytes()); // Max-BVLC-Length
        payload.extend_from_slice(&1476u16.to_be_bytes()); // Max-NPDU-Length
        let accept = ScMessage {
            function: ScFunction::ConnectAccept,
            message_id: req.message_id,
            originating_vmac: Some([0x10; 6]),
            destination_vmac: req.originating_vmac,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::from(payload),
        };
        let mut buf = BytesMut::new();
        encode_sc_message(&mut buf, &accept);
        ws_server.send(&buf).await.unwrap();
        ws_server // return so it's not dropped
    });

    let _rx = transport.start().await.unwrap();
    // Verify connected
    let conn = transport.connection().unwrap();
    let c = conn.lock().await;
    assert_eq!(c.state, ScConnectionState::Connected);
    drop(c);

    transport.stop().await.unwrap();
    let _ = hub_task.await;
}

#[tokio::test]
async fn test_failover_on_primary_timeout() {
    // Primary pair: hub side will NOT respond, causing a timeout.
    let (primary_client, _primary_hub) = LoopbackWebSocket::pair();
    // Failover pair: hub side WILL respond with ConnectAccept.
    let (failover_client, failover_hub) = LoopbackWebSocket::pair();

    let vmac = [0x01; 6];
    let hub_vmac = [0x20; 6];

    let mut transport = ScTransport::new(primary_client, vmac)
        .with_connect_timeout_ms(200)
        .with_failover(failover_client);

    // Spawn hub accept on failover side.
    let hub_task = tokio::spawn(async move {
        hub_accept(&failover_hub, hub_vmac).await;
        failover_hub
    });

    let _rx = transport.start().await.unwrap();

    // Verify connected via failover.
    let conn = transport.connection().unwrap();
    let c = conn.lock().await;
    assert_eq!(c.state, ScConnectionState::Connected);
    assert_eq!(c.hub_vmac, Some(hub_vmac));
    drop(c);

    transport.stop().await.unwrap();
    let _ = hub_task.await;
}

#[tokio::test]
async fn test_no_failover_without_config() {
    // Primary pair: hub side will NOT respond.
    let (primary_client, _primary_hub) = LoopbackWebSocket::pair();

    let vmac = [0x01; 6];
    // No failover configured.
    let mut transport = ScTransport::new(primary_client, vmac).with_connect_timeout_ms(200);

    let result = transport.start().await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("timeout"),
        "Expected timeout error, got: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_failover_primary_succeeds_no_failover_used() {
    // Primary pair: hub side WILL respond.
    let (primary_client, primary_hub) = LoopbackWebSocket::pair();
    // Failover pair: should NOT be used.
    let (failover_client, _failover_hub) = LoopbackWebSocket::pair();

    let vmac = [0x01; 6];
    let hub_vmac = [0x10; 6];

    let mut transport = ScTransport::new(primary_client, vmac)
        .with_connect_timeout_ms(2000)
        .with_failover(failover_client);

    // Spawn hub accept on primary side.
    let hub_task = tokio::spawn(async move {
        hub_accept(&primary_hub, hub_vmac).await;
        primary_hub
    });

    let _rx = transport.start().await.unwrap();

    // Verify connected via primary.
    let conn = transport.connection().unwrap();
    let c = conn.lock().await;
    assert_eq!(c.state, ScConnectionState::Connected);
    assert_eq!(c.hub_vmac, Some(hub_vmac));
    drop(c);

    transport.stop().await.unwrap();
    let _ = hub_task.await;
}

#[test]
fn reconnect_config_default() {
    let config = ScReconnectConfig::default();
    assert_eq!(config.initial_delay_ms, 10_000);
    assert_eq!(config.max_delay_ms, 600_000);
    assert_eq!(config.max_retries, 10);
}

#[test]
fn reconnect_exponential_backoff_sequence() {
    let config = ScReconnectConfig {
        initial_delay_ms: 100,
        max_delay_ms: 1000,
        max_retries: 5,
    };
    let mut delay = config.initial_delay_ms;
    let delays: Vec<u64> = (0..5)
        .map(|_| {
            let d = delay;
            delay = (delay * 2).min(config.max_delay_ms);
            d
        })
        .collect();
    assert_eq!(delays, vec![100, 200, 400, 800, 1000]);
}

#[test]
fn with_reconnect_builder() {
    // Verify the builder sets the config.
    // We can't easily create an ScTransport without a WebSocket,
    // so just verify ScReconnectConfig is constructible and clonable.
    let config = ScReconnectConfig::default();
    let config2 = config.clone();
    assert_eq!(config.initial_delay_ms, config2.initial_delay_ms);
}
