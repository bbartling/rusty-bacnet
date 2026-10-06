//! DeviceCommunicationControl and the discovery messages the server sends
//! itself (Clause 16.1, #1388). Under DISABLE_INITIATION a Who-Is still gets
//! its I-Am, but a Who-Has gets no I-Have and an I-Am announcement fails
//! without sending anything.
//!
//! Each test restricts initiation with a real DeviceCommunicationControl
//! request lasting one minute, then enables initiation again either by
//! letting that timer run out on the paused clock or with a DCC ENABLE.
//! Requests come from the wire harness peer, and the server answers it
//! directly.
use super::cov_wire_test_support::*;
use super::test_transport::SendLog;
use super::*;
use bacnet_services::who_has::{IHaveRequest, WhoHasObject, WhoHasRequest};
use bacnet_types::enums::EnableDisable;

/// The harness server, with initiation restricted for one minute by a DCC
/// request it has acknowledged.
async fn under_disable_initiation() -> Harness {
    under_disable_initiation_with(DiscoveryPolicy::default()).await
}

/// [`under_disable_initiation`] with the discovery limiter on `policy`.
async fn under_disable_initiation_with(policy: DiscoveryPolicy) -> Harness {
    let mut h = Harness::start(ServerConfig {
        dcc_policy: DccPolicy::LegacyPermissive,
        discovery_policy: policy,
        ..Default::default()
    })
    .await;
    h.dcc(EnableDisable::DISABLE_INITIATION, Some(1)).await;
    assert_eq!(response(&h).await, Ok(()));
    assert_eq!(h.server.comm_state(), DccState::DisableInitiation);
    h
}

/// Let the DCC request's minute run out.
async fn timer_expires(h: &Harness) {
    tokio::time::advance(Duration::from_secs(60)).await;
    h.settle().await;
    assert_eq!(
        h.server.comm_state(),
        DccState::Enable,
        "the timer enabled initiation"
    );
}

/// Enable initiation again with an acknowledged DCC ENABLE.
async fn enable(h: &mut Harness) {
    h.dcc(EnableDisable::ENABLE, None).await;
    assert_eq!(response(h).await, Ok(()));
    assert_eq!(h.server.comm_state(), DccState::Enable);
}

/// Whether `error` is the refusal of an I-Am announcement under DCC.
fn communication_disabled(error: &Error) -> bool {
    matches!(error, Error::Protocol { class, code }
        if *class == ErrorClass::SERVICES.to_raw() as u32
            && *code == ErrorCode::COMMUNICATION_DISABLED.to_raw() as u32)
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
        range: None,
        object: WhoHasObject::Name("AV-1".into()),
    }
    .encode(&mut body)
    .unwrap();
    unconfirmed(h, UnconfirmedServiceChoice::WHO_HAS, body).await;
}

/// A Who-Is for every device.
async fn who_is(h: &Harness) {
    let mut body = BytesMut::new();
    WhoIsRequest { range: None }.encode(&mut body);
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
    // The limiter measures its window on the paused clock (#1548), so the
    // window must outlast the timer's minute: had the limiter recorded the
    // held-back answer, the repeat below would then be coalesced away.
    let h = under_disable_initiation_with(DiscoveryPolicy {
        coalesce_window: Duration::from_secs(3600),
        ..DiscoveryPolicy::default()
    })
    .await;
    who_has_av1(&h).await;
    assert!(sent_to_peer(&h).is_empty(), "no I-Have under DCC");

    // The same request again, from the same peer.
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
    assert!(communication_disabled(&refused), "{refused:?}");
    assert_eq!(i_am_broadcasts(&log), 0);
    assert_eq!(h.server.discovery_counters().i_am_sent, 0);

    timer_expires(&h).await;
    h.server.broadcast_i_am().await.unwrap();
    assert_eq!(i_am_broadcasts(&log), 1);
    assert_eq!(h.server.discovery_counters().i_am_sent, 1);
}

/// The DCC check sits ahead of the discovery limiter, so a held-back Who-Has
/// records nothing for the limiter to coalesce a repeat against. Here the
/// repeat comes right after a DCC ENABLE, well inside a coalescing window
/// stretched to an hour: had the limiter recorded the held-back answer, the
/// repeat would be coalesced and get no I-Have.
#[tokio::test(start_paused = true)]
async fn a_who_has_held_back_by_dcc_is_answered_after_enable_inside_the_coalescing_window() {
    let mut h = under_disable_initiation_with(DiscoveryPolicy {
        coalesce_window: Duration::from_secs(3600),
        ..DiscoveryPolicy::default()
    })
    .await;
    who_has_av1(&h).await;
    assert!(sent_to_peer(&h).is_empty(), "no I-Have under DCC");
    assert_eq!(h.server.discovery_counters().requests_coalesced, 0);

    enable(&mut h).await;
    who_has_av1(&h).await;
    let [answer]: [UnconfirmedRequestPdu; 1] = sent_to_peer(&h).try_into().unwrap();
    assert_eq!(answer.service_choice, UnconfirmedServiceChoice::I_HAVE);
    let counters = h.server.discovery_counters();
    assert_eq!((counters.i_have_sent, counters.requests_coalesced), (1, 0));
}

#[tokio::test(start_paused = true)]
async fn an_i_am_broadcaster_handle_is_refused_under_disable_initiation() {
    let mut h = under_disable_initiation().await;
    let announcer = h.server.i_am_broadcaster();
    let log = h.server.test_network().transport().sent();
    let refused = announcer.broadcast_i_am().await.unwrap_err();
    assert!(communication_disabled(&refused), "{refused:?}");
    assert_eq!(i_am_broadcasts(&log), 0);

    enable(&mut h).await;
    announcer.broadcast_i_am().await.unwrap();
    assert_eq!(i_am_broadcasts(&log), 1);
}
