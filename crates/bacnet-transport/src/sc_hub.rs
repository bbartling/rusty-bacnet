//! BACnet/SC Hub — a minimal hub that accepts TLS WebSocket connections
//! from BACnet/SC nodes and relays messages between them.
//!
//! The hub performs three duties:
//! 1. **Connection handshake** — responds to `ConnectRequest` with `ConnectAccept`.
//! 2. **Message relay** — forwards `EncapsulatedNpdu` to the destination VMAC
//!    (unicast) or to all connected nodes (broadcast).
//! 3. **Heartbeat** — responds to `HeartbeatRequest` with `HeartbeatAck`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bacnet_types::enums::{ErrorClass, ErrorCode};
use bytes::{Bytes, BytesMut};
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, warn};

mod relay;

use relay::{
    build_hub_relay_message, hub_relay_recipient_vmacs, hub_relay_target, HubRelayReject,
    HubRelayTarget,
};

use crate::sc_frame::{
    decode_sc_message, encode_sc_message, ScFunction, ScMessage, Vmac, BACNET_SC_HUB_SUBPROTOCOL,
    BROADCAST_VMAC,
};

type TlsStream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
type WsSink = SplitSink<WebSocketStream<TlsStream>, Message>;
type DeviceUuid = [u8; 16];

const HUB_MAX_BVLC_LENGTH: u16 = 1476;
const HUB_MAX_NPDU_LENGTH: u16 = 1476;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectRequestVmacDisposition {
    Accept,
    CloseReserved,
    Nak(ErrorClass, ErrorCode),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayLimitDecision {
    Send,
    DropMaxNpdu,
    DropMaxBvlc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HubClientRegistrationDecision {
    Accept,
    Replace { old_vmac: Vmac },
    NakDuplicateVmac,
    NakMaxClients,
}

/// Per-client state tracked by the hub.
struct HubClient {
    sink: Arc<Mutex<WsSink>>,
    /// Device UUID from the accepted peer's Connect-Request.
    device_uuid: DeviceUuid,
    /// Maximum encoded BACnet/SC BVLC message length this client can accept.
    max_bvlc: u16,
    /// Maximum NPDU length this client can accept (from ConnectRequest).
    max_npdu: u16,
    /// Last activity time (epoch seconds) — updated on every received message.
    last_activity: Arc<std::sync::atomic::AtomicU64>,
}

/// Shared state for the hub: connected clients keyed by VMAC.
type Clients = Arc<Mutex<HashMap<Vmac, HubClient>>>;

/// A minimal BACnet/SC hub.
///
/// Listens on a TLS WebSocket port, accepts SC node connections, performs the
/// Connect-Request/Connect-Accept handshake, and relays `EncapsulatedNpdu`
/// messages between connected nodes.
pub struct ScHub {
    hub_vmac: Vmac,
    /// Device UUID (16 bytes, RFC 4122).
    #[allow(dead_code)]
    hub_uuid: DeviceUuid,
    listener_task: Option<JoinHandle<()>>,
    local_addr: Option<SocketAddr>,
}

impl ScHub {
    /// Start the hub, binding to `bind_addr` (e.g. `"127.0.0.1:0"` for a
    /// random port).
    ///
    /// The hub begins accepting TLS WebSocket connections immediately on a
    /// background task.
    pub async fn start(
        bind_addr: &str,
        tls_acceptor: TlsAcceptor,
        hub_vmac: Vmac,
    ) -> Result<Self, bacnet_types::error::Error> {
        Self::start_with_uuid(bind_addr, tls_acceptor, hub_vmac, [0u8; 16]).await
    }

    /// Start the hub with a specific Device UUID.
    pub async fn start_with_uuid(
        bind_addr: &str,
        tls_acceptor: TlsAcceptor,
        hub_vmac: Vmac,
        hub_uuid: DeviceUuid,
    ) -> Result<Self, bacnet_types::error::Error> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| bacnet_types::error::Error::Encoding(format!("Hub bind failed: {e}")))?;

        let local_addr = listener.local_addr().map_err(|e| {
            bacnet_types::error::Error::Encoding(format!("Hub could not read local address: {e}"))
        })?;

        debug!("BACnet/SC hub listening on {local_addr}");

        let clients: Clients = Arc::new(Mutex::new(HashMap::new()));

        let task = tokio::spawn(accept_loop(
            listener,
            tls_acceptor,
            hub_vmac,
            hub_uuid,
            clients,
        ));

        Ok(Self {
            hub_vmac,
            hub_uuid,
            listener_task: Some(task),
            local_addr: Some(local_addr),
        })
    }

    /// The address the hub is listening on (available after [`Self::start`]).
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// The hub's own VMAC.
    pub fn hub_vmac(&self) -> Vmac {
        self.hub_vmac
    }

    /// Stop the hub, aborting the listener task.
    pub async fn stop(&mut self) {
        if let Some(task) = self.listener_task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

// ---------------------------------------------------------------------------
// Accept loop
// ---------------------------------------------------------------------------

// Closure passed to `accept_hdr_async` returns the upstream tungstenite
// `ErrorResponse`, whose size is fixed by the library. The clippy lint can't
// be addressed without changing the foreign signature.
#[allow(clippy::result_large_err)]
async fn accept_loop(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    hub_vmac: Vmac,
    hub_uuid: DeviceUuid,
    clients: Clients,
) {
    // Track active TCP connections (pre-handshake) to limit DoS surface.
    let active_connections = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    const MAX_ACTIVE_CONNECTIONS: usize = 512;

    // Heartbeat sweep: periodically check for idle clients and send HeartbeatRequest.
    // Per Annex AB.6.3, peers initiate heartbeats to detect idle/dead connections.
    const HEARTBEAT_CHECK_INTERVAL_SECS: u64 = 30;
    const HEARTBEAT_IDLE_THRESHOLD_SECS: u64 = 60;
    {
        let clients_for_hb = clients.clone();
        let next_msg_id = std::sync::atomic::AtomicU16::new(0x8000); // hub message IDs start high
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                HEARTBEAT_CHECK_INTERVAL_SECS,
            ));
            loop {
                interval.tick().await;
                let now = now_secs();
                // Snapshot idle clients
                let idle_clients: Vec<(Vmac, Arc<Mutex<WsSink>>)> = {
                    let map = clients_for_hb.lock().await;
                    map.iter()
                        .filter(|(_, c)| {
                            let last = c.last_activity.load(std::sync::atomic::Ordering::Acquire);
                            now.saturating_sub(last) > HEARTBEAT_IDLE_THRESHOLD_SECS
                        })
                        .map(|(vmac, c)| (*vmac, Arc::clone(&c.sink)))
                        .collect()
                };
                for (vmac, sink) in idle_clients {
                    let msg_id = next_msg_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let hb = ScMessage {
                        function: ScFunction::HeartbeatRequest,
                        message_id: msg_id,
                        originating_vmac: None,
                        destination_vmac: None,
                        dest_options: Vec::new(),
                        data_options: Vec::new(),
                        payload: Bytes::new(),
                    };
                    let mut buf = BytesMut::new();
                    encode_sc_message(&mut buf, &hb);
                    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                        let mut w = sink.lock().await;
                        w.send(Message::Binary(buf.to_vec().into())).await
                    })
                    .await;
                    if let Err(_) | Ok(Err(_)) = result {
                        warn!("Hub: heartbeat send failed for {vmac:02x?}, removing client");
                        let mut map = clients_for_hb.lock().await;
                        if map
                            .get(&vmac)
                            .is_some_and(|client| Arc::ptr_eq(&client.sink, &sink))
                        {
                            map.remove(&vmac);
                        }
                    }
                }
            }
        });
    }

    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("Hub accept error: {e}");
                continue;
            }
        };

        // Reject if too many pre-handshake connections
        let current = active_connections.load(std::sync::atomic::Ordering::Relaxed);
        if current >= MAX_ACTIVE_CONNECTIONS {
            warn!("Hub: rejecting connection from {peer_addr} — max active connections ({MAX_ACTIVE_CONNECTIONS}) reached");
            drop(tcp_stream);
            continue;
        }
        active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        debug!("Hub: new TCP connection from {peer_addr}");

        let acceptor = tls_acceptor.clone();
        let clients = clients.clone();
        let conn_counter = active_connections.clone();

        tokio::spawn(async move {
            // Decrement connection counter when this task exits (any path).
            struct ConnGuard(std::sync::Arc<std::sync::atomic::AtomicUsize>);
            impl Drop for ConnGuard {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            let _guard = ConnGuard(conn_counter);
            // TLS handshake
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("Hub TLS handshake failed for {peer_addr}: {e}");
                    return;
                }
            };

            // WebSocket upgrade — require and echo the BACnet/SC hub subprotocol.
            let ws_stream = match tokio_tungstenite::accept_hdr_async(
                tls_stream,
                |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                 mut response: tokio_tungstenite::tungstenite::handshake::server::Response|
                 -> Result<
                    tokio_tungstenite::tungstenite::handshake::server::Response,
                    tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
                > {
                    if !offers_websocket_subprotocol(request, BACNET_SC_HUB_SUBPROTOCOL) {
                        return Err(websocket_subprotocol_error_response());
                    }
                    response.headers_mut().insert(
                        "Sec-WebSocket-Protocol",
                        BACNET_SC_HUB_SUBPROTOCOL.parse().unwrap(),
                    );
                    Ok(response)
                },
            )
            .await
            {
                Ok(ws) => ws,
                Err(e) => {
                    warn!("Hub WebSocket upgrade failed for {peer_addr}: {e}");
                    return;
                }
            };

            let (write, read) = ws_stream.split();
            let write = Arc::new(Mutex::new(write));

            handle_client(peer_addr, hub_vmac, hub_uuid, read, write, clients).await;
        });
    }
}

// ---------------------------------------------------------------------------
// Per-client handler
// ---------------------------------------------------------------------------

async fn handle_client(
    peer_addr: SocketAddr,
    hub_vmac: Vmac,
    hub_uuid: DeviceUuid,
    mut read: futures_util::stream::SplitStream<WebSocketStream<TlsStream>>,
    write: Arc<Mutex<WsSink>>,
    clients: Clients,
) {
    let mut client_vmac: Option<Vmac> = None;
    let client_activity: Arc<std::sync::atomic::AtomicU64> =
        Arc::new(std::sync::atomic::AtomicU64::new(now_secs()));

    while let Some(msg_result) = read.next().await {
        // Update last-activity timestamp for heartbeat tracking
        client_activity.store(now_secs(), std::sync::atomic::Ordering::Release);

        let data = match msg_result {
            Ok(Message::Binary(data)) => data.to_vec(),
            Ok(Message::Close(_)) => {
                debug!("Hub: client {peer_addr} sent close");
                break;
            }
            Ok(Message::Ping(_) | Message::Pong(_)) => continue,
            Ok(_) => {
                warn!("Hub: non-binary frame from {peer_addr}, closing with 1003");
                let mut w = write.lock().await;
                let _ = w
                    .send(Message::Close(Some(
                        tokio_tungstenite::tungstenite::protocol::CloseFrame {
                            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Unsupported,
                            reason: "BACnet/SC requires binary frames".into(),
                        },
                    )))
                    .await;
                break;
            }
            Err(e) => {
                warn!("Hub: recv error from {peer_addr}: {e}");
                break;
            }
        };

        if data.len() > HUB_MAX_BVLC_LENGTH as usize {
            warn!(
                "Hub: frame from {peer_addr} is {} bytes, exceeds hub Max-BVLC-Length {}, dropping",
                data.len(),
                HUB_MAX_BVLC_LENGTH
            );
            continue;
        }

        let sc_msg = match decode_sc_message(&data) {
            Ok(m) => m,
            Err(e) => {
                warn!("Hub: decode error from {peer_addr}: {e}");
                continue;
            }
        };

        if let Some(registered_vmac) = client_vmac {
            if !registered_client_matches_sink(&clients, registered_vmac, &write).await {
                debug!("Hub: client {peer_addr} (vmac={registered_vmac:02x?}) was superseded");
                break;
            }
        }

        match sc_msg.function {
            ScFunction::ConnectRequest => {
                // AB.2.10.1 defines a fixed 26-byte Connect-Request payload.
                if sc_msg.payload.len() != 26 {
                    warn!(
                        "Hub: ConnectRequest from {peer_addr} has {} payload bytes, expected 26",
                        sc_msg.payload.len()
                    );
                    let error_code = if sc_msg.payload.len() < 26 {
                        ErrorCode::MESSAGE_INCOMPLETE
                    } else {
                        ErrorCode::UNEXPECTED_DATA
                    };
                    let nak = build_bvlc_result_nak(
                        sc_msg.message_id,
                        ScFunction::ConnectRequest,
                        ErrorClass::COMMUNICATION,
                        error_code,
                    );
                    let mut buf = BytesMut::new();
                    encode_sc_message(&mut buf, &nak);
                    let mut w = write.lock().await;
                    let _ = w.send(Message::Binary(buf.to_vec().into())).await;
                    break;
                }
                let mut vmac = [0u8; 6];
                vmac.copy_from_slice(&sc_msg.payload[0..6]);
                // Parse Device UUID (bytes 6..22) and max lengths (bytes 22..26).
                let mut client_uuid = [0u8; 16];
                client_uuid.copy_from_slice(&sc_msg.payload[6..22]);
                let client_max_bvlc = u16::from_be_bytes([sc_msg.payload[22], sc_msg.payload[23]]);
                let client_max_npdu = u16::from_be_bytes([sc_msg.payload[24], sc_msg.payload[25]]);
                debug!("Hub: ConnectRequest from {peer_addr} vmac={vmac:02x?} max_bvlc={client_max_bvlc} max_npdu={client_max_npdu}");

                match connect_request_vmac_disposition(vmac, hub_vmac) {
                    ConnectRequestVmacDisposition::Accept => {}
                    ConnectRequestVmacDisposition::CloseReserved => {
                        warn!("Hub: rejecting reserved VMAC {vmac:02x?} from {peer_addr}");
                        break;
                    }
                    ConnectRequestVmacDisposition::Nak(error_class, error_code) => {
                        warn!("Hub: VMAC collision for {vmac:02x?} from {peer_addr}");
                        let error_result = build_bvlc_result_nak(
                            sc_msg.message_id,
                            ScFunction::ConnectRequest,
                            error_class,
                            error_code,
                        );
                        let mut buf = BytesMut::new();
                        encode_sc_message(&mut buf, &error_result);
                        let mut w = write.lock().await;
                        let _ = w.send(Message::Binary(buf.to_vec().into())).await;
                        break;
                    }
                }

                // Check for VMAC collision / Device UUID replacement and
                // register atomically under a single lock to prevent TOCTOU races.
                const MAX_SC_CLIENTS: usize = 256;
                let superseded_sink = {
                    let mut map = clients.lock().await;
                    let decision = hub_client_registration_decision(
                        vmac,
                        client_uuid,
                        map.iter().map(|(vmac, client)| (*vmac, client.device_uuid)),
                        MAX_SC_CLIENTS,
                    );
                    let superseded_sink = match decision {
                        HubClientRegistrationDecision::Accept => None,
                        HubClientRegistrationDecision::Replace { old_vmac } => {
                            let old_client = map.remove(&old_vmac);
                            if old_vmac == vmac {
                                debug!(
                                    "Hub: replacing existing connection for VMAC {vmac:02x?} and Device UUID from {peer_addr}"
                                );
                            } else {
                                debug!(
                                    "Hub: replacing existing Device UUID connection from VMAC {old_vmac:02x?} with {vmac:02x?}"
                                );
                            }
                            old_client.and_then(|client| {
                                if Arc::ptr_eq(&client.sink, &write) {
                                    None
                                } else {
                                    Some(client.sink)
                                }
                            })
                        }
                        HubClientRegistrationDecision::NakDuplicateVmac => {
                            warn!("Hub: VMAC collision for {vmac:02x?} from {peer_addr}");
                            drop(map); // release lock before sending
                            let error_result = build_bvlc_result_nak(
                                sc_msg.message_id,
                                ScFunction::ConnectRequest,
                                ErrorClass::COMMUNICATION,
                                ErrorCode::NODE_DUPLICATE_VMAC,
                            );
                            let mut buf = BytesMut::new();
                            encode_sc_message(&mut buf, &error_result);
                            let mut w = write.lock().await;
                            let _ = w.send(Message::Binary(buf.to_vec().into())).await;
                            break;
                        }
                        HubClientRegistrationDecision::NakMaxClients => {
                            warn!("SC Hub: max clients reached, rejecting connection");
                            drop(map);
                            let error_result = build_bvlc_result_nak(
                                sc_msg.message_id,
                                ScFunction::ConnectRequest,
                                ErrorClass::RESOURCES,
                                ErrorCode::OTHER,
                            );
                            let mut buf = BytesMut::new();
                            encode_sc_message(&mut buf, &error_result);
                            let mut w = write.lock().await;
                            let _ = w.send(Message::Binary(buf.to_vec().into())).await;
                            break;
                        }
                    };
                    map.insert(
                        vmac,
                        HubClient {
                            sink: write.clone(),
                            device_uuid: client_uuid,
                            max_bvlc: client_max_bvlc,
                            max_npdu: client_max_npdu,
                            last_activity: client_activity.clone(),
                        },
                    );
                    superseded_sink
                };
                client_vmac = Some(vmac);

                if let Some(sink) = superseded_sink {
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                            let mut old = sink.lock().await;
                            old.send(Message::Close(None)).await
                        })
                        .await;
                    });
                }

                let mut accept_payload = Vec::with_capacity(26);
                accept_payload.extend_from_slice(&hub_vmac);
                accept_payload.extend_from_slice(&hub_uuid);
                accept_payload.extend_from_slice(&HUB_MAX_BVLC_LENGTH.to_be_bytes());
                accept_payload.extend_from_slice(&HUB_MAX_NPDU_LENGTH.to_be_bytes());
                let accept = ScMessage {
                    function: ScFunction::ConnectAccept,
                    message_id: sc_msg.message_id,
                    originating_vmac: None,
                    destination_vmac: None,
                    dest_options: Vec::new(),
                    data_options: Vec::new(),
                    payload: Bytes::from(accept_payload),
                };
                let mut buf = BytesMut::new();
                encode_sc_message(&mut buf, &accept);

                let mut w = write.lock().await;
                if let Err(e) = w.send(Message::Binary(buf.to_vec().into())).await {
                    warn!("Hub: failed to send ConnectAccept to {peer_addr}: {e}");
                    break;
                }
            }

            ScFunction::HeartbeatRequest => {
                let ack = ScMessage {
                    function: ScFunction::HeartbeatAck,
                    message_id: sc_msg.message_id,
                    originating_vmac: None,
                    destination_vmac: None,
                    dest_options: Vec::new(),
                    data_options: Vec::new(),
                    payload: Bytes::new(),
                };
                let mut buf = BytesMut::new();
                encode_sc_message(&mut buf, &ack);

                let mut w = write.lock().await;
                if let Err(e) = w.send(Message::Binary(buf.to_vec().into())).await {
                    warn!("Hub: failed to send HeartbeatAck to {peer_addr}: {e}");
                    break;
                }
            }

            ScFunction::DisconnectRequest => {
                debug!("Hub: DisconnectRequest from {peer_addr}");
                let ack = ScMessage {
                    function: ScFunction::DisconnectAck,
                    message_id: sc_msg.message_id,
                    originating_vmac: None,
                    destination_vmac: None,
                    dest_options: Vec::new(),
                    data_options: Vec::new(),
                    payload: Bytes::new(),
                };
                let mut buf = BytesMut::new();
                encode_sc_message(&mut buf, &ack);

                let mut w = write.lock().await;
                let _ = w.send(Message::Binary(buf.to_vec().into())).await;
                break;
            }

            ScFunction::EncapsulatedNpdu => {
                let Some(registered_vmac) = client_vmac else {
                    warn!("Hub: EncapsulatedNpdu before ConnectRequest from {peer_addr} — sending NAK");
                    let nak = build_bvlc_result_nak(
                        sc_msg.message_id,
                        ScFunction::EncapsulatedNpdu,
                        ErrorClass::COMMUNICATION,
                        ErrorCode::OTHER,
                    );
                    let mut buf = BytesMut::new();
                    encode_sc_message(&mut buf, &nak);
                    let mut w = write.lock().await;
                    let _ = w.send(Message::Binary(buf.to_vec().into())).await;
                    continue;
                };

                let relay_target = match hub_relay_target(&sc_msg) {
                    Ok(target) => target,
                    Err(HubRelayReject::OriginatingVmacPresent) => {
                        warn!(
                            "Hub: EncapsulatedNpdu from {peer_addr} had Originating VMAC, dropping"
                        );
                        continue;
                    }
                    Err(HubRelayReject::MissingDestinationVmac) => {
                        warn!(
                            "Hub: EncapsulatedNpdu from {peer_addr} missing Destination VMAC, dropping"
                        );
                        continue;
                    }
                };

                let npdu_len = sc_msg.payload.len();

                let relay_msg = build_hub_relay_message(&sc_msg, registered_vmac, relay_target);
                let mut relay_buf = BytesMut::new();
                encode_sc_message(&mut relay_buf, &relay_msg);
                let relay_bytes: Vec<u8> = relay_buf.to_vec();
                let relay_len = relay_bytes.len();

                if relay_target == HubRelayTarget::Broadcast {
                    // Parallel broadcast relay with per-client timeout
                    let sinks: Vec<(Vmac, Arc<Mutex<WsSink>>)> = {
                        let map = clients.lock().await;
                        let recipients = hub_relay_recipient_vmacs(
                            relay_target,
                            registered_vmac,
                            map.keys().copied(),
                        );
                        recipients
                            .into_iter()
                            .filter_map(|vmac| {
                                let c = map.get(&vmac)?;
                                match relay_limit_decision(
                                    npdu_len,
                                    relay_len,
                                    c.max_npdu,
                                    c.max_bvlc,
                                ) {
                                    RelayLimitDecision::Send => Some((vmac, Arc::clone(&c.sink))),
                                    RelayLimitDecision::DropMaxNpdu => {
                                        warn!(
                                            "Hub: broadcast NPDU ({npdu_len} bytes) exceeds target max_npdu ({}) for {vmac:02x?}, dropping for target",
                                            c.max_npdu
                                        );
                                        None
                                    }
                                    RelayLimitDecision::DropMaxBvlc => {
                                        warn!(
                                            "Hub: broadcast BVLC ({relay_len} bytes) exceeds target max_bvlc ({}) for {vmac:02x?}, dropping for target",
                                            c.max_bvlc
                                        );
                                        None
                                    }
                                }
                            })
                            .collect()
                    };
                    let relay_shared = Bytes::from(relay_bytes);
                    let futs: Vec<_> = sinks
                        .into_iter()
                        .map(|(vmac, sink)| {
                            let data = relay_shared.clone();
                            async move {
                                let result = tokio::time::timeout(
                                    std::time::Duration::from_secs(5),
                                    async {
                                        let mut w = sink.lock().await;
                                        w.send(Message::Binary(data.to_vec().into())).await
                                    },
                                )
                                .await;
                                if let Err(_) | Ok(Err(_)) = result {
                                    warn!("Hub: broadcast relay failed to {vmac:02x?}");
                                }
                            }
                        })
                        .collect();
                    futures_util::future::join_all(futs).await;
                } else if let HubRelayTarget::Unicast(dest) = relay_target {
                    let target = {
                        let map = clients.lock().await;
                        let recipients = hub_relay_recipient_vmacs(
                            relay_target,
                            registered_vmac,
                            map.keys().copied(),
                        );
                        recipients.into_iter().next().and_then(|vmac| {
                            map.get(&vmac)
                                .map(|c| (Arc::clone(&c.sink), c.max_npdu, c.max_bvlc))
                        })
                    };
                    if let Some((sink, max_npdu, max_bvlc)) = target {
                        match relay_limit_decision(npdu_len, relay_len, max_npdu, max_bvlc) {
                            RelayLimitDecision::Send => {
                                let mut w = sink.lock().await;
                                if let Err(e) = w.send(Message::Binary(relay_bytes.into())).await {
                                    warn!("Hub: unicast relay error to {dest:02x?}: {e}");
                                }
                            }
                            RelayLimitDecision::DropMaxNpdu => warn!(
                                "Hub: NPDU ({npdu_len} bytes) exceeds target max_npdu ({max_npdu}) for {dest:02x?}, dropping"
                            ),
                            RelayLimitDecision::DropMaxBvlc => warn!(
                                "Hub: BVLC ({relay_len} bytes) exceeds target max_bvlc ({max_bvlc}) for {dest:02x?}, dropping"
                            ),
                        }
                    } else {
                        debug!("Hub: no client with vmac {dest:02x?} for unicast relay");
                    }
                }
            }

            other => {
                debug!("Hub: unknown function {other:?} from {peer_addr}, sending NAK");
                let nak = build_bvlc_result_nak(
                    sc_msg.message_id,
                    other,
                    ErrorClass::COMMUNICATION,
                    unexpected_bvlc_function_error_code(other),
                );
                let mut buf = BytesMut::new();
                encode_sc_message(&mut buf, &nak);
                let mut w = write.lock().await;
                let _ = w.send(Message::Binary(buf.to_vec().into())).await;
            }
        }
    }

    if let Some(vmac) = client_vmac {
        let mut map = clients.lock().await;
        let removed = map
            .get(&vmac)
            .is_some_and(|client| Arc::ptr_eq(&client.sink, &write));
        if removed {
            map.remove(&vmac);
            debug!("Hub: client {peer_addr} (vmac={vmac:02x?}) disconnected");
        } else {
            debug!("Hub: client {peer_addr} (vmac={vmac:02x?}) disconnected after replacement");
        }
    }
}

fn offers_websocket_subprotocol(
    request: &tokio_tungstenite::tungstenite::handshake::server::Request,
    expected: &str,
) -> bool {
    request
        .headers()
        .get("Sec-WebSocket-Protocol")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').any(|p| p.trim() == expected))
        .unwrap_or(false)
}

fn websocket_subprotocol_error_response(
) -> tokio_tungstenite::tungstenite::handshake::server::ErrorResponse {
    tokio_tungstenite::tungstenite::http::Response::builder()
        .status(tokio_tungstenite::tungstenite::http::StatusCode::BAD_REQUEST)
        .body(Some(format!(
            "BACnet/SC hub requires WebSocket subprotocol {BACNET_SC_HUB_SUBPROTOCOL}"
        )))
        .expect("static WebSocket error response is valid")
}

fn unexpected_bvlc_function_error_code(function: ScFunction) -> ErrorCode {
    match function {
        ScFunction::Unknown(_) => ErrorCode::BVLC_FUNCTION_UNKNOWN,
        _ => ErrorCode::UNEXPECTED_DATA,
    }
}

fn connect_request_vmac_disposition(vmac: Vmac, hub_vmac: Vmac) -> ConnectRequestVmacDisposition {
    if vmac == crate::sc_frame::UNKNOWN_VMAC || vmac == BROADCAST_VMAC {
        ConnectRequestVmacDisposition::CloseReserved
    } else if vmac == hub_vmac {
        ConnectRequestVmacDisposition::Nak(
            ErrorClass::COMMUNICATION,
            ErrorCode::NODE_DUPLICATE_VMAC,
        )
    } else {
        ConnectRequestVmacDisposition::Accept
    }
}

fn hub_client_registration_decision<I>(
    requested_vmac: Vmac,
    device_uuid: DeviceUuid,
    existing_clients: I,
    max_clients: usize,
) -> HubClientRegistrationDecision
where
    I: IntoIterator<Item = (Vmac, DeviceUuid)>,
{
    let mut count = 0usize;
    let mut requested_vmac_owner = None;
    let mut existing_uuid_vmac = None;

    for (existing_vmac, existing_uuid) in existing_clients {
        count += 1;
        if existing_vmac == requested_vmac {
            requested_vmac_owner = Some(existing_uuid);
        }
        if existing_uuid == device_uuid {
            existing_uuid_vmac = Some(existing_vmac);
        }
    }

    if requested_vmac_owner.is_some_and(|owner_uuid| owner_uuid != device_uuid) {
        return HubClientRegistrationDecision::NakDuplicateVmac;
    }

    if let Some(old_vmac) = existing_uuid_vmac {
        return HubClientRegistrationDecision::Replace { old_vmac };
    }

    if count >= max_clients {
        HubClientRegistrationDecision::NakMaxClients
    } else {
        HubClientRegistrationDecision::Accept
    }
}

async fn registered_client_matches_sink(
    clients: &Clients,
    registered_vmac: Vmac,
    sink: &Arc<Mutex<WsSink>>,
) -> bool {
    let map = clients.lock().await;
    map.get(&registered_vmac)
        .is_some_and(|client| Arc::ptr_eq(&client.sink, sink))
}

fn relay_limit_decision(
    npdu_len: usize,
    encoded_bvlc_len: usize,
    max_npdu: u16,
    max_bvlc: u16,
) -> RelayLimitDecision {
    if npdu_len > max_npdu as usize {
        RelayLimitDecision::DropMaxNpdu
    } else if encoded_bvlc_len > max_bvlc as usize {
        RelayLimitDecision::DropMaxBvlc
    } else {
        RelayLimitDecision::Send
    }
}

/// Build a BVLC-Result NAK message.
fn build_bvlc_result_nak(
    message_id: u16,
    result_for: ScFunction,
    error_class: ErrorClass,
    error_code: ErrorCode,
) -> ScMessage {
    let error_class = error_class.to_raw().to_be_bytes();
    let error_code = error_code.to_raw().to_be_bytes();
    ScMessage {
        function: ScFunction::Result,
        message_id,
        originating_vmac: None,
        destination_vmac: None,
        dest_options: Vec::new(),
        data_options: Vec::new(),
        payload: Bytes::from(vec![
            result_for.to_raw(),
            0x01, // NAK
            0x00, // error header marker
            error_class[0],
            error_class[1],
            error_code[0],
            error_code[1],
        ]),
    }
}

/// Current time in seconds since UNIX epoch.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests;
