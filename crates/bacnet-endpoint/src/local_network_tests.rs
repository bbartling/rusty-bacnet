//! Once an endpoint session knows the number of its own network (#1403),
//! traffic it starts for a station on that network goes as local traffic: to
//! the station's MAC with no DNET. A routed read naming the number goes to its
//! DADR, and the answer from there completes it; one relayed back with this
//! network as its SNET does not. Another network keeps its DNET, every
//! network does while the number is unknown, and answers keep the route their
//! request arrived by. The source Audit cases are in `source`.
//!
//! The capture link carries B/IP-shaped MACs: the session is `10.0.0.1`, the
//! peer `10.0.0.3`, behind router `10.0.0.9` when routed. The number is
//! learned through the session's own Network-Number-Is intake.
use super::*;
use crate::roles::EndpointApduDestination;
use bacnet_encoding::apdu::{decode_apdu, encode_apdu, ComplexAck, ConfirmedRequest};
use bacnet_encoding::npdu::{decode_npdu, encode_npdu, Npdu, NpduAddress};
use bacnet_services::read_property::{ReadPropertyACK, ReadPropertyRequest};
use bacnet_transport::bvll::encode_bip_mac;
use bacnet_transport::port::{ReceivedNpdu, TransportProvenance};
use bacnet_types::enums::{ConfirmedServiceChoice, ObjectType, PropertyIdentifier};
use bacnet_types::MacAddr;
use bytes::{Bytes, BytesMut};
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::time::{timeout, Duration};

#[path = "local_network_source_tests.rs"]
mod source;

/// The number of the network the session is attached to.
const THIS_NETWORK: u16 = 77;
const REMOTE_NETWORK: u16 = 5;
const SELF: u8 = 1;
const PEER: u8 = 3;
const ROUTER: u8 = 9;
const PORT: u16 = 0xBAC0;

fn host(last: u8) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, last), PORT)
}

fn mac(last: u8) -> MacAddr {
    MacAddr::from_slice(&encode_bip_mac([10, 0, 0, last], PORT))
}

fn oid(kind: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(kind, instance).unwrap()
}

fn analog() -> ObjectIdentifier {
    oid(ObjectType::ANALOG_INPUT, 1)
}

async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    timeout(Duration::from_secs(5), future)
        .await
        .expect("local network fixture made no progress")
}

/// One frame the session handed the link: its link MAC (empty for a link
/// broadcast) and NPDU.
struct Sent {
    link: MacAddr,
    npdu: Bytes,
}

/// A B/IP-shaped link that records every send and takes injected input.
struct Capture {
    local: MacAddr,
    inbound: Option<mpsc::Receiver<ReceivedNpdu>>,
    outbound: mpsc::Sender<Sent>,
    lease: Option<Arc<()>>,
}

impl Capture {
    fn record(&self, link: &[u8], npdu: &[u8]) -> Result<(), Error> {
        self.outbound
            .try_send(Sent {
                link: MacAddr::from_slice(link),
                npdu: Bytes::copy_from_slice(npdu),
            })
            .expect("bounded send observation");
        Ok(())
    }
}

impl TransportPort for Capture {
    fn bip_broadcast_endpoint(&self) -> Option<SocketAddrV4> {
        Some(host(255))
    }
    fn supports_local_nonrouter_number_controls(&self) -> bool {
        true
    }
    fn normal_bip_endpoint(&self) -> Option<SocketAddrV4> {
        Some(host(SELF))
    }
    fn retain_network_port_lease_internal(&mut self, lease: Arc<()>) -> Result<(), Error> {
        self.lease = Some(lease);
        Ok(())
    }
    async fn start(&mut self) -> Result<mpsc::Receiver<ReceivedNpdu>, Error> {
        Ok(self.inbound.take().expect("started once"))
    }
    async fn stop(&mut self) -> Result<(), Error> {
        self.lease = None;
        Ok(())
    }
    async fn send_unicast(&self, npdu: &[u8], mac: &[u8]) -> Result<(), Error> {
        self.record(mac, npdu)
    }
    async fn send_broadcast(&self, npdu: &[u8]) -> Result<(), Error> {
        self.record(&[], npdu)
    }
    fn local_mac(&self) -> &[u8] {
        &self.local
    }
    fn local_receive_apdu_capacity(&self) -> u16 {
        1476
    }
}

/// Where a frame went: its link MAC and the NPDU's DNET/DADR, if any.
#[derive(Debug, PartialEq, Eq)]
struct Route {
    link: MacAddr,
    destination: Option<NpduAddress>,
}

/// Straight to `station` on this link, with no DNET.
fn local(station: u8) -> Route {
    Route {
        link: mac(station),
        destination: None,
    }
}

/// Through link MAC `link` (empty for a link broadcast) to the peer on
/// `network`.
fn routed(link: MacAddr, network: u16) -> Route {
    Route {
        link,
        destination: Some(NpduAddress {
            network,
            mac_address: mac(PEER),
        }),
    }
}

/// The peer on `network`, as a routed SNET/SADR or DNET/DADR.
fn peer_on(network: u16) -> Option<NpduAddress> {
    Some(NpduAddress {
        network,
        mac_address: mac(PEER),
    })
}

struct Endpoint {
    session: EndpointSession<Capture>,
    inbound: mpsc::Sender<ReceivedNpdu>,
    sent: mpsc::Receiver<Sent>,
}

impl Endpoint {
    /// A session of `role` on the capture link, not yet started.
    fn new(role: SessionRole) -> Self {
        let (inbound, input) = mpsc::channel(32);
        let (outbound, sent) = mpsc::channel(32);
        let transport = Capture {
            local: mac(SELF),
            inbound: Some(input),
            outbound,
            lease: None,
        };
        let config = SessionConfig {
            apdu_timeout_ms: 5_000,
            ..SessionConfig::default()
        };
        Self {
            session: EndpointSession::new(transport, role, config).unwrap(),
            inbound,
            sent,
        }
    }

    /// A started session of `role` that has learned `THIS_NETWORK`, or no
    /// number at all.
    async fn started(role: SessionRole, learned: bool) -> Self {
        let mut endpoint = Self::new(role);
        let db = crate::DeviceIdentity::new(123, 42)
            .unwrap()
            .build_database()
            .unwrap();
        endpoint.session = endpoint.session.with_database(db);
        endpoint.start(learned).await;
        endpoint
    }

    async fn start(&mut self, learned: bool) {
        bounded(self.session.start()).await.unwrap();
        if learned {
            self.learn(THIS_NETWORK).await;
        }
    }

    /// Announce `number` by local broadcast, then query it: the Number owner
    /// takes controls in order, so its answer holds the announced number and
    /// has published it.
    async fn learn(&mut self, number: u16) {
        let [high, low] = number.to_be_bytes();
        let announcement = [1, 0x80, 0x13, high, low, 0];
        self.deliver(mac(ROUTER), Bytes::copy_from_slice(&announcement), true)
            .await;
        self.deliver(mac(PEER), Bytes::from_static(&[1, 0x80, 0x12]), false)
            .await;
        let answer = self.next().await;
        assert!(answer.link.is_empty(), "Network-Number-Is is broadcast");
        assert_eq!(answer.npdu.as_ref(), announcement);
    }

    async fn deliver(&self, link: MacAddr, npdu: Bytes, group: bool) {
        self.inbound
            .send(ReceivedNpdu {
                npdu,
                source_mac: link,
                link_layer_group: group,
                data_attributes: Vec::new(),
                provenance: TransportProvenance::unverified(),
                direct_response: None,
                reply_tx: None,
            })
            .await
            .unwrap();
    }

    /// Hand the session `apdu` from link MAC `link`, with `source` as its
    /// SNET/SADR when relayed by a router.
    async fn deliver_apdu(&self, apdu: Apdu, link: MacAddr, source: Option<NpduAddress>) {
        let mut payload = BytesMut::new();
        encode_apdu(&mut payload, &apdu).unwrap();
        let mut npdu = BytesMut::new();
        encode_npdu(
            &mut npdu,
            &Npdu {
                source,
                payload: payload.freeze(),
                ..Npdu::default()
            },
        )
        .unwrap();
        self.deliver(link, npdu.freeze(), false).await;
    }

    async fn next(&mut self) -> Sent {
        bounded(self.sent.recv()).await.expect("capture link open")
    }

    /// Start a ReadProperty of the peer's analog input at `destination`.
    fn read(
        &self,
        destination: EndpointApduDestination,
    ) -> tokio::task::JoinHandle<Result<ReadPropertyACK, Error>> {
        let client = self.session.cloned_client_handle().unwrap();
        tokio::spawn(async move {
            client
                .read_property_with_destination(
                    destination,
                    Vec::new(),
                    analog(),
                    PropertyIdentifier::PRESENT_VALUE,
                    None,
                )
                .await
        })
    }

    /// The confirmed request the session sends next, and where it went.
    async fn request(&mut self) -> (Route, ConfirmedRequest) {
        let sent = self.next().await;
        let npdu = decode_npdu(sent.npdu).unwrap();
        let Apdu::ConfirmedRequest(request) = decode_apdu(npdu.payload).unwrap() else {
            panic!("a confirmed request")
        };
        let route = Route {
            link: sent.link,
            destination: npdu.destination,
        };
        (route, request)
    }

    async fn stop(mut self) {
        bounded(self.session.stop()).await.unwrap();
    }
}

/// The ReadPropertyACK answering `request` with Unsigned `value`.
fn ack(request: &ConfirmedRequest, value: u8) -> Apdu {
    let mut service = BytesMut::new();
    ReadPropertyACK {
        object_identifier: analog(),
        property_identifier: PropertyIdentifier::PRESENT_VALUE,
        property_array_index: None,
        property_value: vec![0x21, value],
    }
    .encode(&mut service);
    Apdu::ComplexAck(ComplexAck {
        segmented: false,
        more_follows: false,
        invoke_id: request.invoke_id,
        sequence_number: None,
        proposed_window_size: None,
        service_choice: ConfirmedServiceChoice::READ_PROPERTY,
        service_ack: service.freeze(),
    })
}

fn routed_read(network: u16) -> EndpointApduDestination {
    EndpointApduDestination::Routed {
        destination_network: network,
        destination_mac: mac(PEER),
        router_mac: mac(ROUTER),
    }
}

fn routed_by_broadcast(network: u16) -> EndpointApduDestination {
    EndpointApduDestination::RoutedViaLocalBroadcast {
        destination_network: network,
        destination_mac: mac(PEER),
    }
}

#[tokio::test]
async fn routed_reads_naming_this_network_go_local_and_the_direct_answer_completes_them() {
    for role in [SessionRole::ClientOnly, SessionRole::Both] {
        let mut endpoint = Endpoint::started(role, true).await;
        for destination in [routed_read(THIS_NETWORK), routed_by_broadcast(THIS_NETWORK)] {
            let read = endpoint.read(destination);
            let (route, request) = endpoint.request().await;
            assert_eq!(route, local(PEER), "{role:?}");
            // An answer relayed with this network as its SNET is not from the
            // MAC the request went to, so only the direct one completes it.
            endpoint
                .deliver_apdu(ack(&request, 1), mac(ROUTER), peer_on(THIS_NETWORK))
                .await;
            endpoint
                .deliver_apdu(ack(&request, 2), mac(PEER), None)
                .await;
            let answer = bounded(read).await.unwrap().unwrap();
            assert_eq!(answer.property_value, [0x21, 2], "{role:?}");
            assert_eq!(endpoint.session.active_leases(), 0);
        }
        endpoint.stop().await;
    }
}

#[tokio::test]
async fn routed_reads_keep_their_dnet_for_another_network_or_an_unknown_number() {
    for role in [SessionRole::ClientOnly, SessionRole::Both] {
        for learned in [true, false] {
            let mut endpoint = Endpoint::started(role, learned).await;
            // With the number known only another network is routed; while it
            // is unknown, this network is routed by its number as well.
            let network = if learned {
                REMOTE_NETWORK
            } else {
                THIS_NETWORK
            };
            for (destination, link) in [
                (routed_read(network), mac(ROUTER)),
                (routed_by_broadcast(network), MacAddr::new()),
            ] {
                let read = endpoint.read(destination);
                let (route, request) = endpoint.request().await;
                assert_eq!(route, routed(link, network), "{role:?}, learned {learned}");
                endpoint
                    .deliver_apdu(ack(&request, 3), mac(ROUTER), peer_on(network))
                    .await;
                let answer = bounded(read).await.unwrap().unwrap();
                assert_eq!(answer.property_value, [0x21, 3]);
            }
            endpoint.stop().await;
        }
    }
}

#[tokio::test]
async fn a_registered_ports_configured_number_is_local_from_startup() {
    let port = oid(ObjectType::NETWORK_PORT, 2);
    let identity = crate::DeviceIdentity::new(123, 42)
        .unwrap()
        .with_bip_port(2, THIS_NETWORK.into(), *host(SELF).ip(), PORT)
        .unwrap();
    let db = identity.build_database().unwrap();
    let mut endpoint = Endpoint::new(SessionRole::Both);
    endpoint.session = endpoint
        .session
        .with_database(db)
        .with_identity(identity)
        .with_registered_network_port(port);
    // No Number control arrives: the port's number is published at startup.
    endpoint.start(false).await;
    let read = endpoint.read(routed_read(THIS_NETWORK));
    let (route, request) = endpoint.request().await;
    assert_eq!(route, local(PEER));
    endpoint
        .deliver_apdu(ack(&request, 4), mac(PEER), None)
        .await;
    assert_eq!(
        bounded(read).await.unwrap().unwrap().property_value,
        [0x21, 4]
    );
    endpoint.stop().await;
}

#[tokio::test]
async fn answers_keep_the_route_their_request_arrived_by() {
    for role in [SessionRole::ServerOnly, SessionRole::Both] {
        let mut endpoint = Endpoint::started(role, true).await;
        let egress = endpoint.session.egress.as_ref().unwrap();
        assert_eq!(egress.local_network_number().get(), Some(THIS_NETWORK));
        let mut service = BytesMut::new();
        ReadPropertyRequest {
            object_identifier: oid(ObjectType::DEVICE, 123),
            property_identifier: PropertyIdentifier::OBJECT_IDENTIFIER,
            property_array_index: None,
        }
        .encode(&mut service);
        let request = Apdu::ConfirmedRequest(ConfirmedRequest {
            segmented: false,
            more_follows: false,
            segmented_response_accepted: false,
            max_segments: None,
            max_apdu_length: 1476,
            invoke_id: 42,
            sequence_number: None,
            proposed_window_size: None,
            service_choice: ConfirmedServiceChoice::READ_PROPERTY,
            service_request: service.freeze(),
        });
        // A request relayed from this network by its number is answered the
        // way it came, through the router that relayed it.
        endpoint
            .deliver_apdu(request, mac(ROUTER), peer_on(THIS_NETWORK))
            .await;
        let sent = endpoint.next().await;
        let npdu = decode_npdu(sent.npdu).unwrap();
        let route = Route {
            link: sent.link,
            destination: npdu.destination,
        };
        assert_eq!(route, routed(mac(ROUTER), THIS_NETWORK), "{role:?}");
        assert!(
            matches!(decode_apdu(npdu.payload).unwrap(), Apdu::ComplexAck(ack) if ack.invoke_id == 42)
        );
        endpoint.stop().await;
    }
}
