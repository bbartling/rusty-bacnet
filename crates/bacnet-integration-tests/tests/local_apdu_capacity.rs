//! Raw local declaration is distinct from the ConfirmedRequest header bucket.
use bacnet_encoding::{
    apdu::{decode_apdu, Apdu},
    npdu::decode_npdu,
};
use bacnet_objects::{
    database::ObjectDatabase,
    device::{DeviceConfig, DeviceObject},
};
use bacnet_server::server::{BACnetServer, ServerConfig};
use bacnet_services::who_is::IAmRequest;
use bacnet_transport::{loopback::LoopbackTransport, port::TransportPort};
use std::time::Duration;

#[tokio::test]
async fn raw_1474_device_and_server_declaration_emit_iam_1474() {
    let (transport, mut peer) = LoopbackTransport::pair(vec![1], vec![2]);
    let mut incoming = peer.start().await.unwrap();
    let mut db = ObjectDatabase::new();
    db.add(Box::new(
        DeviceObject::new(DeviceConfig {
            instance: 893,
            max_apdu_length: 1474,
            ..Default::default()
        })
        .unwrap(),
    ))
    .unwrap();
    let mut server = BACnetServer::start(
        ServerConfig {
            max_apdu_length: 1474,
            ..Default::default()
        },
        db,
        transport,
    )
    .await
    .expect("raw Device/I-Am1474 is a valid local declaration");
    server.broadcast_i_am().await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(2), incoming.recv())
        .await
        .unwrap()
        .unwrap();
    let npdu = decode_npdu(received.npdu).unwrap();
    let Apdu::UnconfirmedRequest(apdu) = decode_apdu(npdu.payload).unwrap() else {
        panic!("expected I-Am")
    };
    assert_eq!(apdu.service_choice.to_raw(), 0);
    assert_eq!(
        IAmRequest::decode(&apdu.service_request)
            .unwrap()
            .max_apdu_length,
        1474
    );
    server.stop().await.unwrap();
}

use bacnet_transport::port::ReceivedNpdu;
use bacnet_types::{enums::ObjectType, error::Error, primitives::ObjectIdentifier};
use std::{
    future::{poll_fn, Future},
    sync::{
        atomic::{AtomicU16, AtomicUsize, Ordering},
        Arc,
    },
    task::Poll,
};
use tokio::sync::mpsc;

/// A deliberately asymmetric link: changing remote egress never changes intake.
struct CapacityPort {
    inner: LoopbackTransport,
    local: u16,
    remote: Arc<AtomicU16>,
    starts: Arc<AtomicUsize>,
}
impl TransportPort for CapacityPort {
    async fn start(&mut self) -> Result<mpsc::Receiver<ReceivedNpdu>, Error> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        self.inner.start().await
    }
    async fn stop(&mut self) -> Result<(), Error> {
        self.inner.stop().await
    }
    fn abort(&mut self) {
        self.inner.abort();
    }
    async fn send_unicast(&self, bytes: &[u8], mac: &[u8]) -> Result<(), Error> {
        self.inner.send_unicast(bytes, mac).await
    }
    async fn send_broadcast(&self, bytes: &[u8]) -> Result<(), Error> {
        self.inner.send_broadcast(bytes).await
    }
    fn local_mac(&self) -> &[u8] {
        self.inner.local_mac()
    }
    fn local_receive_apdu_capacity(&self) -> u16 {
        self.local
    }
    fn egress_apdu_limit(&self) -> u16 {
        self.remote.load(Ordering::SeqCst)
    }
}
fn device(raw: u32) -> DeviceObject {
    DeviceObject::new(DeviceConfig {
        instance: 893,
        max_apdu_length: raw,
        ..Default::default()
    })
    .unwrap()
}
fn database(raw: Option<u32>) -> ObjectDatabase {
    let mut db = ObjectDatabase::new();
    if let Some(raw) = raw {
        db.add(Box::new(device(raw))).unwrap();
    }
    db
}
fn port(local: u16) -> (CapacityPort, LoopbackTransport) {
    let (inner, peer) = LoopbackTransport::pair(vec![1], vec![2]);
    (
        CapacityPort {
            inner,
            local,
            remote: Arc::new(AtomicU16::new(206)),
            starts: Arc::new(AtomicUsize::new(0)),
        },
        peer,
    )
}
async fn iam(incoming: &mut mpsc::Receiver<ReceivedNpdu>) -> IAmRequest {
    let bytes = tokio::time::timeout(Duration::from_secs(2), incoming.recv())
        .await
        .unwrap()
        .unwrap();
    let Apdu::UnconfirmedRequest(req) =
        decode_apdu(decode_npdu(bytes.npdu).unwrap().payload).unwrap()
    else {
        panic!("expected I-Am")
    };
    assert_eq!(req.service_choice.to_raw(), 0);
    IAmRequest::decode(&req.service_request).unwrap()
}

#[tokio::test]
async fn local_capacity_clamps_ceiling_and_never_tracks_remote_egress() {
    for (local, ceiling, effective) in [
        (480, 1476, 480),
        (1476, u32::MAX, 1476),
        (1476, 50, 50),
        (1476, 127, 127),
    ] {
        let (transport, mut peer) = port(local);
        let remote = Arc::clone(&transport.remote);
        let mut incoming = peer.start().await.unwrap();
        let mut server = BACnetServer::start(
            ServerConfig {
                max_apdu_length: ceiling,
                ..Default::default()
            },
            database(Some(effective)),
            transport,
        )
        .await
        .unwrap();
        for outgoing in [50, 480, 1476] {
            remote.store(outgoing, Ordering::SeqCst);
            server.broadcast_i_am().await.unwrap();
            assert_eq!(iam(&mut incoming).await.max_apdu_length, effective);
        }
        server.stop().await.unwrap();
    }
}

#[tokio::test]
async fn invalid_raw_and_mismatched_device_fail_before_transport_start() {
    for (local, ceiling, declared) in [
        (1476, 49, 1476),
        (49, 1476, 1476),
        (480, 1476, 1476),
        (1476, 1474, 1476),
    ] {
        let (transport, _peer) = port(local);
        let starts = Arc::clone(&transport.starts);
        assert!(BACnetServer::start(
            ServerConfig {
                max_apdu_length: ceiling,
                ..Default::default()
            },
            database(Some(declared)),
            transport
        )
        .await
        .is_err());
        assert_eq!(starts.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn queued_iam_rechecks_replacement_before_encoding_or_limiter_accounting() {
    let (transport, mut peer) = port(1476);
    let mut incoming = peer.start().await.unwrap();
    let mut server = BACnetServer::start(
        ServerConfig {
            max_apdu_length: 1474,
            ..Default::default()
        },
        database(Some(1474)),
        transport,
    )
    .await
    .unwrap();
    let db = Arc::clone(server.database());
    let oid = ObjectIdentifier::new(ObjectType::DEVICE, 893).unwrap();
    let mut guard = db.write().await;
    let mut send = Box::pin(server.broadcast_i_am());
    // Poll through synchronous queue admission while the worker cannot read DB.
    assert!(poll_fn(|cx| Poll::Ready(send.as_mut().poll(cx)))
        .await
        .is_pending());
    guard.remove(&oid).unwrap();
    guard.add(Box::new(device(1476))).unwrap();
    drop(guard);
    assert!(send.await.is_err());
    assert!(incoming.try_recv().is_err());
    assert_eq!(server.discovery_counters().i_am_sent, 0);
    assert_eq!(server.discovery_counters().response_bytes_sent, 0);
    {
        let mut db = db.write().await;
        db.remove(&oid).unwrap();
        db.add(Box::new(device(1474))).unwrap();
    }
    server.broadcast_i_am().await.unwrap();
    assert_eq!(iam(&mut incoming).await.max_apdu_length, 1474);
    assert_eq!(server.discovery_counters().i_am_sent, 1);
    db.write().await.remove(&oid).unwrap();
    assert!(server.broadcast_i_am().await.is_err());
    assert!(incoming.try_recv().is_err());
    server.stop().await.unwrap();
}

#[tokio::test]
async fn no_device_starts_without_iam_and_matching_later_device_recovers() {
    let (transport, mut peer) = port(1476);
    let mut incoming = peer.start().await.unwrap();
    let mut server = BACnetServer::start(ServerConfig::default(), database(None), transport)
        .await
        .unwrap();
    assert!(server.broadcast_i_am().await.is_err());
    assert!(incoming.try_recv().is_err());
    server
        .database()
        .write()
        .await
        .add(Box::new(device(1476)))
        .unwrap();
    server.broadcast_i_am().await.unwrap();
    assert_eq!(iam(&mut incoming).await.max_apdu_length, 1476);
    server.stop().await.unwrap();
}

#[path = "local_apdu_capacity/sc.rs"]
mod sc;
