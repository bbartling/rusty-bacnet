use super::*;
use crate::server::dcc_outcomes::trace_tests::Capture;

fn dcc(id: u8) -> Apdu {
    let Apdu::ConfirmedRequest(mut req) = request(id) else {
        unreachable!()
    };
    req.service_choice = ConfirmedServiceChoice::DEVICE_COMMUNICATION_CONTROL;
    req.service_request = Bytes::from_static(b"\x19\x00");
    Apdu::ConfirmedRequest(req)
}

#[tokio::test]
async fn dcc_outcomes_exclude_global_peer_and_abort_fallback_rejections() {
    for (global, peer) in [(1, 16), (4, 1)] {
        let capture = Capture::default();
        let _subscriber = tracing::subscriber::set_default(capture.clone());
        let (mut server, _, mut started) = fixture_with_config(
            "overload",
            ServerConfig {
                request_admission_policy: RequestAdmissionPolicy {
                    max_confirmed_in_flight: global,
                    max_confirmed_in_flight_per_peer: peer,
                    confirmed_recovery_reserve: 0,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await;
        dispatch(&server, dcc(1), None, None).await;
        let mut completions = vec![observed(&mut started).await];
        for id in 2..=9 {
            dispatch(&server, dcc(id), None, None).await;
            completions.push(observed(&mut started).await);
        }
        dispatch(&server, dcc(10), None, None).await;
        let counters = server.request_admission_counters();
        assert_eq!(
            counters.confirmed_global_overloaded_total,
            if global == 1 { 9 } else { 0 }
        );
        assert_eq!(
            counters.confirmed_peer_overloaded_total,
            if peer == 1 { 9 } else { 0 }
        );
        assert_eq!(counters.abort_admitted_total, 8);
        assert_eq!(counters.confirmed_fallback_dropped_total, 1);
        assert_eq!(server.dcc_outcome_counters().policy_denied_total, 1);
        assert_eq!(capture.0.lock().unwrap().len(), 1);
        server.stop().await.unwrap();
        for completion in completions {
            completion.await.unwrap();
        }
        assert_eq!(capture.0.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn dcc_outcomes_recovery_denied_duplicate_overload_and_shutdown() {
    // Current-thread runtime: this scoped default also covers spawned handlers.
    // No global subscriber is installed and no events escape the test.
    let capture = Capture::default();
    let _subscriber = tracing::subscriber::set_default(capture.clone());
    let (mut server, _, mut started) = fixture_with_config(
        "outcomes admission",
        ServerConfig {
            request_admission_policy: RequestAdmissionPolicy {
                max_confirmed_in_flight: 2,
                confirmed_recovery_reserve: 1,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    dispatch(&server, request(1), None, None).await;
    let ordinary = observed(&mut started).await;
    assert!(
        tracing::dispatcher::get_default(|d| d.is::<Capture>()),
        "lost scoped subscriber before dispatch"
    );
    dispatch(&server, dcc(2), None, None).await;
    dispatch(&server, dcc(2), None, None).await; // pending before its first poll
    assert_eq!(
        server.request_admission_counters().confirmed_admitted_total,
        2
    );
    let recovery = observed(&mut started).await;
    assert_eq!(server.dcc_outcome_counters().policy_denied_total, 1);
    assert_eq!(
        server.request_admission_counters().recovery_admitted_total,
        1
    );
    assert_eq!(capture.0.lock().unwrap().len(), 1);
    assert_eq!(capture.0.lock().unwrap()[0]["outcome"], "policy_denied");
    // Its response has now issued, although the transport Result is held.
    // Reuse is a new operation and the independent recovery task quota is full.
    dispatch(&server, dcc(2), None, None).await;
    let reused_abort = observed(&mut started).await;
    assert_eq!(
        server.request_admission_counters().confirmed_admitted_total,
        2
    );
    dispatch(&server, dcc(3), None, None).await; // recovery partition full
    let abort = observed(&mut started).await;
    assert_eq!(
        server
            .request_admission_counters()
            .recovery_overloaded_total,
        2
    );
    assert_eq!(server.dcc_outcome_counters().policy_denied_total, 1);
    assert_eq!(capture.0.lock().unwrap().len(), 1);
    begin_stop(&mut server).await;
    ordinary.await.unwrap();
    recovery.await.unwrap();
    abort.await.unwrap();
    reused_abort.await.unwrap();
    dispatch(&server, dcc(4), None, None).await;
    assert_eq!(
        server
            .request_admission_counters()
            .confirmed_shutdown_rejected_total,
        1
    );
    assert_eq!(server.dcc_outcome_counters().policy_denied_total, 1);
    assert_eq!(capture.0.lock().unwrap().len(), 1);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn disable_initiation_still_admits_requests_and_answers_overload_with_abort() {
    // The server refuses DISABLE, so DISABLE_INITIATION is the only state DCC
    // leaves it in: admission and the overload Abort carry on unchanged.
    let (mut server, _tx, mut started) = small_fixture().await;
    server.comm_state.set_for_test(DccState::DisableInitiation);
    dispatch(&server, request(1), None, None).await;
    let answered = observed(&mut started).await;
    dispatch(&server, request(2), None, None).await; // capacity is one
    let aborted = observed(&mut started).await;
    let counters = server.request_admission_counters();
    assert_eq!(counters.confirmed_admitted_total, 1);
    assert_eq!(counters.confirmed_overloaded_total, 1);
    assert_eq!(counters.abort_admitted_total, 1);
    {
        let frames = held_sends(&server).frames.lock().unwrap();
        assert!(
            matches!(&frames[..], [Apdu::Error(_) | Apdu::Reject(_), Apdu::Abort(abort)]
                if abort.invoke_id == 2 && abort.abort_reason == AbortReason::OUT_OF_RESOURCES),
            "{frames:?}"
        );
    }
    held_sends(&server).release.notify_waiters();
    answered.await.unwrap();
    aborted.await.unwrap();
    wait_reaped(&server).await;
    dispatch(&server, who_is(), None, None).await;
    let i_am = observed(&mut started).await;
    assert_eq!(
        server
            .request_admission_counters()
            .unconfirmed_admitted_total,
        1
    );
    assert!(matches!(
        held_sends(&server).frames.lock().unwrap().last(),
        Some(Apdu::UnconfirmedRequest(req)) if req.service_choice == UnconfirmedServiceChoice::I_AM
    ));
    held_sends(&server).release.notify_waiters();
    i_am.await.unwrap();
    server.stop().await.unwrap();
}
