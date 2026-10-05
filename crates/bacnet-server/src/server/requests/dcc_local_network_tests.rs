//! A DCC source restriction entry routed through the server's own network
//! number also names the station's direct requests once that number is
//! known (#1458), the identity rule a Device binding follows (#1404).
use super::*;
use crate::server::{DccSource, DccSourceRestriction};
use bacnet_types::network_number::NetworkNumber;

/// The number of the network the server is attached to.
const THIS_NETWORK: u16 = 7;
/// The listed station, B/IP-shaped.
const STATION: [u8; 6] = [10, 0, 0, 3, 0xba, 0xc0];
const OTHER_STATION: [u8; 6] = [10, 0, 0, 4, 0xba, 0xc0];
/// A router on this link, relaying a station's request.
const ROUTER: [u8; 6] = [10, 0, 0, 9, 0xba, 0xc0];

fn restriction(entry: DccSource) -> ServerConfig {
    ServerConfig {
        dcc_policy: DccPolicy::RequirePassword,
        dcc_password: Some("required".into()),
        dcc_source_restriction: Some(DccSourceRestriction::new(vec![entry]).unwrap()),
        ..Default::default()
    }
}

fn routed(network: u16, address: &[u8]) -> NpduAddress {
    NpduAddress {
        network,
        mac_address: MacAddr::from_slice(address),
    }
}

/// An ENABLE with the right password from link MAC `mac`, relayed with
/// `source` as SNET/SADR when one is given, to a server under
/// DISABLE_INITIATION that knows `number` as its network's. Whether the
/// source restriction let it through: a SimpleACK and ENABLE in force, or
/// SERVICE_REQUEST_DENIED and the state untouched.
async fn enable_from(
    config: &ServerConfig,
    number: Option<u16>,
    mac: &[u8],
    source: Option<NpduAddress>,
) -> bool {
    let network = Arc::new(NetworkLayer::new(BipTransport::new(
        Ipv4Addr::LOCALHOST,
        0,
        Ipv4Addr::BROADCAST,
    )));
    if let Some(number) = number {
        network
            .local_network_number()
            .publish(NetworkNumber::configured(number).unwrap());
    }
    let state = comm_state_in(DccState::DisableInitiation);
    let mut data = BytesMut::new();
    DeviceCommunicationControlRequest {
        time_duration: None,
        enable_disable: EnableDisable::ENABLE,
        password: Some("required".into()),
    }
    .encode(&mut data)
    .unwrap();
    let (tx, rx) = oneshot::channel();
    BACnetServer::<BipTransport>::handle_confirmed_request(
        &RequestServices {
            comm_state: Arc::clone(&state),
            ..RequestServices::for_test(network, config.clone())
        },
        &Arc::new(ConfirmedRequestTracker::default()),
        &Arc::new(crate::server::request_tasks::RequestTasks::default()).spawner(),
        mac,
        source,
        ConfirmedRequestPdu {
            segmented: false,
            more_follows: false,
            segmented_response_accepted: false,
            max_segments: None,
            max_apdu_length: 480,
            invoke_id: 42,
            sequence_number: None,
            proposed_window_size: None,
            service_choice: ConfirmedServiceChoice::DEVICE_COMMUNICATION_CONTROL,
            service_request: data.freeze(),
        },
        Some(tx),
    )
    .await;
    let response = decode_apdu(decode_npdu(rx.await.unwrap()).unwrap().payload).unwrap();
    if matches!(response, Apdu::SimpleAck(_)) {
        assert_eq!(state.get(), DccState::Enable);
        true
    } else {
        assert_denied(response);
        assert_eq!(state.get(), DccState::DisableInitiation);
        false
    }
}

#[tokio::test]
async fn a_routed_entry_on_this_network_admits_the_stations_direct_request() {
    let config = restriction(DccSource::Routed {
        network: THIS_NETWORK,
        address: STATION.to_vec(),
    });
    // Once the number is known, the station's own request with no SNET is
    // the source the entry names.
    assert!(enable_from(&config, Some(THIS_NETWORK), &STATION, None).await);
    // Relayed back with this network as SNET, it still matches as written.
    let relayed = routed(THIS_NETWORK, &STATION);
    assert!(enable_from(&config, Some(THIS_NETWORK), &ROUTER, Some(relayed.clone())).await);
    assert!(enable_from(&config, None, &ROUTER, Some(relayed)).await);
}

#[tokio::test]
async fn a_routed_entry_names_no_direct_request_off_this_network() {
    let config = restriction(DccSource::Routed {
        network: THIS_NETWORK,
        address: STATION.to_vec(),
    });
    // While the number is unknown the entry names a routed source only.
    assert!(!enable_from(&config, None, &STATION, None).await);
    // On another network it names a station elsewhere.
    assert!(!enable_from(&config, Some(THIS_NETWORK + 1), &STATION, None).await);
    // Another station on this network is not the one listed.
    assert!(!enable_from(&config, Some(THIS_NETWORK), &OTHER_STATION, None).await);
}

#[tokio::test]
async fn a_direct_entry_still_names_no_routed_request() {
    // Only the routed entry widens: any node on the link could claim this
    // network as SNET and the listed MAC as SADR.
    let config = restriction(DccSource::Direct(STATION.to_vec()));
    assert!(enable_from(&config, Some(THIS_NETWORK), &STATION, None).await);
    let claimed = routed(THIS_NETWORK, &STATION);
    assert!(!enable_from(&config, Some(THIS_NETWORK), &ROUTER, Some(claimed)).await);
}
