//! A write in another device the server has no fresh binding for looks for
//! that device first, with one Who-Is limited to its instance (#1322,
//! Clause 16.10).
//!
//! The harness is `command_remote_write_tests`' without the binding: CMD-1's
//! list 1 writes AO-1 in Device 9, then the local AO-2. Writes are made as a
//! run, or through the run host directly to see the [`RemoteWriteError`]
//! they end with. Who-Is requests are taken from the test transport's send
//! log, and I-Am answers are delivered by hand from the harness peer. The
//! clock is paused, and the server's APDU timeout is the default 3 seconds.
use super::binding_probes::WHO_IS_HOLD_OFF;
use super::command_action_wire_tests::{ao, idle, slot8, state, write, write_pv};
use super::command_remote_write_tests::{
    ack, deliver, device, disable_initiation, remote_write, sent_writes, start_unbound,
};
use super::command_run_stop_tests::db_flags;
use super::command_runs::CommandRunner;
use super::cov_wire_test_support::*;
use super::*;
use crate::command_lists::RunHost;
use bacnet_encoding::apdu::decode_apdu;
use bacnet_types::constructed::BACnetActionCommand;
use tokio::task::JoinHandle;
use tokio::time::Instant as TokioInstant;

/// The APDU timeout: how long a write waits for its device's I-Am.
const WAIT: Duration = Duration::from_secs(3);

/// The Who-Is for Device `instance` alone.
pub(super) fn targeted(instance: u32) -> WhoIsRequest {
    WhoIsRequest {
        low_limit: Some(instance),
        high_limit: Some(instance),
    }
}

/// Take every Who-Is the server has broadcast, with the remote network each
/// was addressed to (`None` for this one).
pub(super) fn who_is_sent(h: &Harness) -> Vec<(Option<u16>, WhoIsRequest)> {
    let log = h.server.test_network().transport().sent();
    let mut frames = log.lock();
    let mut taken = Vec::new();
    frames.retain(|frame| {
        let npdu = frame.decode_npdu();
        match decode_apdu(npdu.payload) {
            Ok(Apdu::UnconfirmedRequest(request))
                if request.service_choice == UnconfirmedServiceChoice::WHO_IS =>
            {
                assert!(frame.broadcast, "a Who-Is goes out as a broadcast");
                let who_is = WhoIsRequest::decode(&request.service_request).unwrap();
                taken.push((npdu.destination.map(|to| to.network), who_is));
                false
            }
            _ => true,
        }
    });
    taken
}

/// Wait for the one Who-Is the server sends next.
pub(super) async fn next_who_is(h: &Harness) -> (Option<u16>, WhoIsRequest) {
    let log = h.server.test_network().transport().sent();
    let sent = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let pushed = log.len() + 1;
            let sent = who_is_sent(h);
            if !sent.is_empty() {
                return sent;
            }
            log.wait_for_len(pushed).await;
        }
    })
    .await
    .expect("a Who-Is");
    let [who_is]: [(Option<u16>, WhoIsRequest); 1] = sent.try_into().unwrap();
    who_is
}

/// Device `instance`'s I-Am.
pub(super) fn i_am(instance: u32) -> Apdu {
    let mut service = BytesMut::new();
    IAmRequest {
        object_identifier: device(instance),
        max_apdu_length: 1476,
        segmentation_supported: Segmentation::NONE,
        vendor_id: 260,
    }
    .encode(&mut service);
    Apdu::UnconfirmedRequest(UnconfirmedRequestPdu {
        service_choice: UnconfirmedServiceChoice::I_AM,
        service_request: service.freeze(),
    })
}

/// How a write ended, and when.
type Ended = (Result<(), RemoteWriteError>, TokioInstant);

/// Start writing AO-1 in Device `instance` through the run host.
fn start_write(h: &Harness, instance: u32) -> JoinHandle<Ended> {
    let runner = CommandRunner::for_server(&h.server);
    let command = BACnetActionCommand {
        device_identifier: Some(device(instance)),
        ..write(ao(1), PropertyValue::Real(80.0), 8)
    };
    tokio::spawn(async move {
        let result = runner.write_remote(device(instance), &command).await;
        (result, TokioInstant::now())
    })
}

#[tokio::test(start_paused = true)]
async fn unbound_command_target_answers_a_targeted_who_is_and_the_write_is_made() {
    let mut h = start_unbound().await;
    write_pv(&mut h, 1, 1).await.unwrap();
    // One Who-Is, on this network, for Device 9 alone; no write yet.
    assert_eq!(next_who_is(&h).await, (None, targeted(9)));
    assert!(sent_writes(&h).is_empty());
    assert_eq!(state(&mut h, 1).await, (true, false));

    // Its I-Am binds Device 9, and the write goes to the peer that sent it.
    deliver(&h, &i_am(9), &PEER, None).await;
    let invoke_id = remote_write(&h).await;
    let unicasts = h.server.test_network().transport().sent().unicasts();
    let request = unicasts
        .iter()
        .find(|frame| matches!(frame.apdu(), Apdu::ConfirmedRequest(_)))
        .expect("the WriteProperty frame");
    assert_eq!(request.mac.as_slice(), PEER);
    h.respond(ack(invoke_id)).await;
    idle(&h, 1).await;
    assert_eq!(db_flags(&h, 1).await, [true, true]);
    assert_eq!(state(&mut h, 1).await, (false, true));

    // The binding stands, so the next run asks nothing.
    write_pv(&mut h, 1, 1).await.unwrap();
    let invoke_id = remote_write(&h).await;
    h.respond(ack(invoke_id)).await;
    idle(&h, 1).await;
    assert!(who_is_sent(&h).is_empty());
}

#[tokio::test(start_paused = true)]
async fn silent_unbound_target_fails_after_the_apdu_timeout_with_one_who_is() {
    let h = start_unbound().await;
    let started = TokioInstant::now();
    let (result, ended) = start_write(&h, 9).await.unwrap();
    assert_eq!(result, Err(RemoteWriteError::Undiscovered));
    assert_eq!(ended - started, WAIT);
    assert_eq!(who_is_sent(&h), [(None, targeted(9))]);
    assert!(sent_writes(&h).is_empty());
    assert_eq!(h.server.notification_transactions.active_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn silent_unbound_command_target_fails_and_the_rest_of_the_list_runs() {
    let mut h = start_unbound().await;
    let started = TokioInstant::now();
    write_pv(&mut h, 1, 1).await.unwrap();
    assert_eq!(next_who_is(&h).await, (None, targeted(9)));
    idle(&h, 1).await;
    assert!(started.elapsed() >= WAIT);
    assert_eq!(db_flags(&h, 1).await, [false, true]);
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Real(80.0));
    assert_eq!(state(&mut h, 1).await, (false, false));
    assert!(sent_writes(&h).is_empty());
    assert!(who_is_sent(&h).is_empty());
}

#[tokio::test(start_paused = true)]
async fn no_who_is_while_dcc_restricts_initiation_or_for_the_wildcard_device() {
    let mut h = start_unbound().await;
    disable_initiation(&h);
    let started = TokioInstant::now();
    let (result, ended) = start_write(&h, 9).await.unwrap();
    assert_eq!(result, Err(RemoteWriteError::Disabled));
    assert_eq!(ended, started);
    write_pv(&mut h, 1, 1).await.unwrap();
    idle(&h, 1).await;
    assert_eq!(db_flags(&h, 1).await, [false, true]);
    assert!(who_is_sent(&h).is_empty());
    assert!(sent_writes(&h).is_empty());

    // With initiation allowed again, the same write asks for Device 9, but a
    // Who-Is for the wildcard instance would call on unconfigured devices,
    // so a write naming it fails at once.
    h.server.comm_state.store(0, Ordering::Release);
    let wildcard = ObjectIdentifier::WILDCARD_INSTANCE;
    let (result, _) = start_write(&h, wildcard).await.unwrap();
    assert_eq!(result, Err(RemoteWriteError::Unbound));
    assert!(who_is_sent(&h).is_empty());
    let write = start_write(&h, 9);
    assert_eq!(next_who_is(&h).await, (None, targeted(9)));
    deliver(&h, &i_am(9), &PEER, None).await;
    let invoke_id = remote_write(&h).await;
    h.respond(ack(invoke_id)).await;
    assert_eq!(write.await.unwrap().0, Ok(()));
}

#[tokio::test(start_paused = true)]
async fn concurrent_writes_to_an_unbound_device_share_one_who_is() {
    let h = start_unbound().await;
    let first = start_write(&h, 9);
    let second = start_write(&h, 9);
    assert_eq!(next_who_is(&h).await, (None, targeted(9)));
    deliver(&h, &i_am(9), &PEER, None).await;
    // The one I-Am lets both writes go, each under its own invoke ID.
    let log = h.server.test_network().transport().sent();
    let sent = tokio::time::timeout(Duration::from_secs(1), async {
        let mut sent = Vec::new();
        loop {
            let pushed = log.len() + 1;
            sent.extend(sent_writes(&h));
            if sent.len() == 2 {
                return sent;
            }
            log.wait_for_len(pushed).await;
        }
    })
    .await
    .expect("both WriteProperty requests");
    assert_ne!(sent[0].0, sent[1].0);
    for (invoke_id, _) in sent {
        h.respond(ack(invoke_id)).await;
    }
    assert_eq!(first.await.unwrap().0, Ok(()));
    assert_eq!(second.await.unwrap().0, Ok(()));
    assert!(who_is_sent(&h).is_empty());
}

#[tokio::test(start_paused = true)]
async fn absent_device_gets_one_who_is_per_hold_off() {
    let h = start_unbound().await;
    let started = TokioInstant::now();
    // Two writes inside the wait share the one Who-Is and its deadline.
    let first = start_write(&h, 9);
    let second = start_write(&h, 9);
    for write in [first, second] {
        let (result, ended) = write.await.unwrap();
        assert_eq!(result, Err(RemoteWriteError::Undiscovered));
        assert_eq!(ended - started, WAIT);
    }
    assert_eq!(who_is_sent(&h).len(), 1);

    // Until a minute after it went out, the next write sends nothing and
    // fails at once.
    tokio::time::advance(WHO_IS_HOLD_OFF - WAIT - Duration::from_millis(1)).await;
    let asked = TokioInstant::now();
    let (result, ended) = start_write(&h, 9).await.unwrap();
    assert_eq!(result, Err(RemoteWriteError::Unbound));
    assert_eq!(ended, asked);
    assert!(who_is_sent(&h).is_empty());

    // Then the device is asked again.
    tokio::time::advance(Duration::from_millis(1)).await;
    let asked = TokioInstant::now();
    let (result, ended) = start_write(&h, 9).await.unwrap();
    assert_eq!(result, Err(RemoteWriteError::Undiscovered));
    assert_eq!(ended - asked, WAIT);
    assert_eq!(who_is_sent(&h), [(None, targeted(9))]);
}

#[tokio::test(start_paused = true)]
async fn who_is_for_a_stale_routed_binding_goes_to_its_network() {
    let h = start_unbound().await;
    // Device 9's last I-Am came through the harness peer from address 0x09
    // on network 5, eleven minutes ago.
    let routed = NpduAddress {
        network: 5,
        mac_address: MacAddr::from_slice(&[0x09]),
    };
    let then = Instant::now()
        .checked_sub(Duration::from_secs(11 * 60))
        .unwrap();
    h.server.device_bindings.write().await.observe_i_am_at(
        device(9),
        &PEER,
        Some(&routed),
        then,
        |_| false,
    );

    let write = start_write(&h, 9);
    assert_eq!(next_who_is(&h).await, (Some(5), targeted(9)));
    deliver(&h, &i_am(9), &PEER, Some(routed.clone())).await;
    let invoke_id = remote_write(&h).await;
    let unicasts = h.server.test_network().transport().sent().unicasts();
    let request = unicasts
        .iter()
        .find(|frame| matches!(frame.apdu(), Apdu::ConfirmedRequest(_)))
        .expect("the WriteProperty frame");
    assert_eq!(request.mac.as_slice(), PEER);
    assert_eq!(request.decode_npdu().destination, Some(routed.clone()));
    deliver(&h, &ack(invoke_id), &PEER, Some(routed)).await;
    assert_eq!(write.await.unwrap().0, Ok(()));
}
