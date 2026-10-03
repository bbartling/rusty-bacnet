//! DeviceCommunicationControl and the discovery messages the server sends
//! itself (Clause 16.1, #1388). Under DISABLE_INITIATION a Who-Is still gets
//! its I-Am, but a Who-Has gets no I-Have and an I-Am announcement fails
//! without sending anything.
//!
//! Each test restricts initiation with a real DeviceCommunicationControl
//! request lasting one minute and, on the paused clock, lets that timer run
//! out to enable initiation again. Requests come from the wire harness peer,
//! and the server answers it directly.
use super::cov_wire_test_support::*;
use super::test_transport::SendLog;
use super::*;
use bacnet_services::who_has::{IHaveRequest, WhoHasObject, WhoHasRequest};
use bacnet_types::enums::EnableDisable;

/// The harness server, with initiation restricted for one minute by a DCC
/// request it has acknowledged.
async fn under_disable_initiation() -> Harness {
    let mut h = Harness::start(ServerConfig {
        dcc_policy: DccPolicy::LegacyPermissive,
        ..Default::default()
    })
    .await;
    h.dcc(EnableDisable::DISABLE_INITIATION, Some(1)).await;
    assert_eq!(response(&h).await, Ok(()));
    assert_eq!(
        h.server.comm_state(),
        EnableDisable::DISABLE_INITIATION.to_raw() as u8
    );
    h
}

/// Let the DCC request's minute run out.
async fn timer_expires(h: &Harness) {
    tokio::time::advance(Duration::from_secs(60)).await;
    h.settle().await;
    assert_eq!(h.server.comm_state(), 0, "the timer enabled initiation");
}

/// Deliver an unconfirmed request from the harness peer and let the server
/// run everything it makes ready.
async fn unconfirmed(h: &Harness, service_choice: UnconfirmedServiceChoice, body: BytesMut) {
    h.respond(Apdu::UnconfirmedRequest(UnconfirmedRequestPdu {
        service_choice,
        service_request: body.freeze(),
    }))
    .await;
    h.settle().await;
}

/// A Who-Has for AV-1 by name, from any device.
async fn who_has_av1(h: &Harness) {
    let mut body = BytesMut::new();
    WhoHasRequest {
        low_limit: None,
        high_limit: None,
        object: WhoHasObject::Name("AV-1".into()),
    }
    .encode(&mut body)
    .unwrap();
    unconfirmed(h, UnconfirmedServiceChoice::WHO_HAS, body).await;
}

/// A Who-Is for every device.
async fn who_is(h: &Harness) {
    let mut body = BytesMut::new();
    WhoIsRequest {
        low_limit: None,
        high_limit: None,
    }
    .encode(&mut body);
    unconfirmed(h, UnconfirmedServiceChoice::WHO_IS, body).await;
}

/// Take every unconfirmed request the server has sent the peer, in order.
fn sent_to_peer(h: &Harness) -> Vec<UnconfirmedRequestPdu> {
    let mut frames = h.frames.lock().unwrap();
    let mut taken = Vec::new();
    frames.retain(|apdu| match apdu {
        Apdu::UnconfirmedRequest(request) => {
            taken.push(request.clone());
            false
        }
        _ => true,
    });
    taken
}

/// How many I-Am broadcasts the transport has carried.
fn i_am_broadcasts(log: &SendLog) -> usize {
    log.broadcasts()
        .iter()
        .filter(|frame| {
            matches!(frame.apdu(), Apdu::UnconfirmedRequest(request)
                if request.service_choice == UnconfirmedServiceChoice::I_AM)
        })
        .count()
}

#[tokio::test(start_paused = true)]
async fn disable_initiation_holds_back_i_have_and_still_answers_who_is() {
    let h = under_disable_initiation().await;
    who_has_av1(&h).await;
    who_is(&h).await;
    let sent: Vec<_> = sent_to_peer(&h)
        .into_iter()
        .map(|request| request.service_choice)
        .collect();
    assert_eq!(sent, [UnconfirmedServiceChoice::I_AM]);
    let counters = h.server.discovery_counters();
    assert_eq!((counters.i_am_sent, counters.i_have_sent), (1, 0));
}

#[tokio::test(start_paused = true)]
async fn a_who_has_held_back_by_dcc_is_answered_once_the_timer_enables_initiation() {
    let h = under_disable_initiation().await;
    who_has_av1(&h).await;
    assert!(sent_to_peer(&h).is_empty(), "no I-Have under DCC");

    // The same request again, from the same peer: nothing the held-back
    // answer left behind coalesces it away.
    timer_expires(&h).await;
    who_has_av1(&h).await;
    let [answer]: [UnconfirmedRequestPdu; 1] = sent_to_peer(&h).try_into().unwrap();
    assert_eq!(answer.service_choice, UnconfirmedServiceChoice::I_HAVE);
    let i_have = IHaveRequest::decode(&answer.service_request).unwrap();
    assert_eq!(i_have.object_identifier, av1());
    assert_eq!(h.server.discovery_counters().i_have_sent, 1);
}

#[tokio::test(start_paused = true)]
async fn broadcast_i_am_fails_under_disable_initiation_and_sends_once_enabled() {
    let h = under_disable_initiation().await;
    let log = h.server.test_network().transport().sent();
    let refused = h.server.broadcast_i_am().await.unwrap_err();
    assert!(
        matches!(refused, Error::Protocol { class, code }
            if class == ErrorClass::SERVICES.to_raw() as u32
                && code == ErrorCode::COMMUNICATION_DISABLED.to_raw() as u32),
        "{refused:?}"
    );
    assert_eq!(i_am_broadcasts(&log), 0);
    assert_eq!(h.server.discovery_counters().i_am_sent, 0);

    timer_expires(&h).await;
    h.server.broadcast_i_am().await.unwrap();
    assert_eq!(i_am_broadcasts(&log), 1);
    assert_eq!(h.server.discovery_counters().i_am_sent, 1);
}
