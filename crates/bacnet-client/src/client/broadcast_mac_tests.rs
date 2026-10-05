//! A confirmed request to the link's broadcast MAC (#1479).
//!
//! With no DNET, the broadcast MAC is a local broadcast, which Clause 6.3
//! keeps for Unconfirmed-Request PDUs. The client refuses a confirmed
//! request to it before any transaction state exists; an unconfirmed
//! request still goes, and so does a routed request whose link DA is the
//! broadcast MAC, since its DNET/DADR name one device.
use bacnet_encoding::apdu::{decode_apdu, Apdu};
use bacnet_encoding::npdu::decode_npdu;
use bacnet_transport::loopback::LoopbackTransport;
use bacnet_transport::port::TransportPort;
use bacnet_types::enums::{AbortReason, ConfirmedServiceChoice, UnconfirmedServiceChoice};
use bacnet_types::error::Error;

use super::{BACnetClient, ClientConfig};

const CLIENT: [u8; 1] = [1];
const PEER: [u8; 1] = [2];
/// The link's broadcast MAC, as on MS/TP.
const BROADCAST: [u8; 1] = [0xFF];

#[tokio::test(start_paused = true)]
async fn a_confirmed_request_to_the_broadcast_mac_is_refused_before_any_state() {
    let (mut transport, mut peer) = LoopbackTransport::pair(CLIENT.to_vec(), PEER.to_vec());
    transport.set_broadcast_mac(BROADCAST.to_vec());
    let mut frames = peer.start().await.unwrap();
    let config = ClientConfig {
        apdu_timeout_ms: 20,
        apdu_retries: 0,
        ..ClientConfig::default()
    };
    let mut client = BACnetClient::start(config, transport).await.unwrap();

    let refused = client
        .confirmed_request(&BROADCAST, ConfirmedServiceChoice::READ_PROPERTY, &[0x0C])
        .await;
    assert!(
        matches!(&refused, Err(Error::Encoding(message))
            if message.contains("not to the link's broadcast MAC")),
        "{refused:?}"
    );
    assert!(
        frames.try_recv().is_err(),
        "a refused request reached the link"
    );
    assert_eq!(client.tsm.lock().await.pending_count(), 0);
    assert_eq!(client.tsm.lock().await.coordinated_active_count(), 0);

    // An unconfirmed request may be broadcast this way.
    client
        .unconfirmed_request(&BROADCAST, UnconfirmedServiceChoice::WHO_IS, &[])
        .await
        .unwrap();
    let who_is = decode_npdu(frames.try_recv().unwrap().npdu).unwrap();
    assert!(matches!(
        decode_apdu(who_is.payload),
        Ok(Apdu::UnconfirmedRequest(_))
    ));

    // A routed request names one device with its DNET/DADR, so its link DA
    // may be the broadcast MAC; it goes out and its transaction times out
    // unanswered.
    let routed = client
        .confirmed_request_routed(
            &BROADCAST,
            5,
            &[7],
            ConfirmedServiceChoice::READ_PROPERTY,
            &[0x0C],
        )
        .await;
    assert!(
        matches!(routed, Err(Error::Abort { reason })
            if reason == AbortReason::TSM_TIMEOUT.to_raw()),
        "{routed:?}"
    );
    let request = decode_npdu(frames.try_recv().unwrap().npdu).unwrap();
    assert!(matches!(
        decode_apdu(request.payload),
        Ok(Apdu::ConfirmedRequest(_))
    ));

    client.stop().await.unwrap();
}
