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
async fn admission_dcc_prechecks_and_duplicate_before_first_poll() {
    let (mut server, _tx, mut started) = small_fixture().await;
    dispatch(&server, request(1), None, None).await;
    dispatch(&server, request(1), None, None).await;
    assert_eq!(
        server.request_admission_counters().confirmed_admitted_total,
        1
    );
    assert_eq!(
        server
            .request_admission_counters()
            .confirmed_overloaded_total,
        0
    );
    observed(&mut started).await;
    server.comm_state.store(1, Ordering::Release);
    dispatch(&server, request(2), None, None).await;
    dispatch(&server, who_is(), None, None).await;
    assert_eq!(
        server
            .request_admission_counters()
            .confirmed_overloaded_total,
        0
    );
    assert_eq!(
        server
            .request_admission_counters()
            .unconfirmed_admitted_total,
        0
    );
    assert_eq!(server.request_admission_counters().abort_active, 0);
    // A no-response DCC discard does not leave a completed duplicate ghost.
    let Apdu::ConfirmedRequest(req) = request(2) else {
        unreachable!()
    };
    assert!(matches!(
        server
            .confirmed_request_tracker
            .begin(&[1], None, TransportProvenance::unverified(), req),
        ConfirmedRequestAdmission::New(_)
    ));
    server.comm_state.store(0, Ordering::Release);
    server.test_network().transport().release.notify_waiters();
    wait_reaped(&server).await;
    dispatch(&server, request(2), None, None).await;
    observed(&mut started).await;
    assert_eq!(
        server.request_admission_counters().confirmed_admitted_total,
        2
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn admission_abort_rechecks_dcc_when_first_polled() {
    let (mut server, _tx, mut started) = small_fixture().await;
    dispatch(&server, request(1), None, None).await;
    observed(&mut started).await;
    dispatch(&server, request(2), None, None).await;
    server.comm_state.store(1, Ordering::Release);
    tokio::time::timeout(Duration::from_secs(2), async {
        while server.request_admission_counters().abort_active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(started.try_recv().is_err());
    assert_eq!(server.request_admission_counters().abort_admitted_total, 1);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn admission_dcc_first_poll_discard_drops_pending_for_reuse() {
    let (mut server, _, mut started) = small_fixture().await;
    dispatch(&server, request(1), None, None).await;
    server.comm_state.store(1, Ordering::Release);
    tokio::time::timeout(Duration::from_secs(2), async {
        while server.request_admission_counters().confirmed_active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(started.try_recv().is_err());
    let Apdu::ConfirmedRequest(req) = request(1) else {
        unreachable!()
    };
    assert!(matches!(
        server
            .confirmed_request_tracker
            .begin(&[1], None, TransportProvenance::unverified(), req),
        ConfirmedRequestAdmission::New(_)
    ));
    server.comm_state.store(0, Ordering::Release);
    dispatch(&server, request(1), None, None).await;
    observed(&mut started).await;
    assert_eq!(
        server.request_admission_counters().confirmed_admitted_total,
        2
    );
    server.stop().await.unwrap();
}
