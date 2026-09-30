//! Recovery capacity and password authorization remain independent.
use super::*;

#[tokio::test]
async fn recovery_classification_is_not_password_authorization() {
    let (mut server, _tx, mut started) = fixture_with_config(
        "recovery",
        ServerConfig {
            dcc_password: Some("required".into()),
            dcc_policy: DccPolicy::RequirePassword,
            ..Default::default()
        },
    )
    .await;
    server.comm_state.store(1, Ordering::Release);
    for (id, password) in [(1, None), (2, Some("wrong"))] {
        dispatch(&server, enable(id, password), source(id), None).await;
        observed(&mut started).await;
        assert_eq!(server.comm_state.load(Ordering::Acquire), 1);
        assert!(
            matches!(held_sends(&server).frames.lock().unwrap().last(), Some(Apdu::Error(e)) if e.error_code == ErrorCode::PASSWORD_FAILURE)
        );
    }
    assert_eq!(server.request_admission_counters().recovery_active, 2);
    dispatch(&server, enable(3, Some("required")), source(3), None).await;
    observed(&mut started).await;
    assert_eq!(server.comm_state.load(Ordering::Acquire), 0);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn recovery_noneligible_requests_cannot_borrow_and_password_capacity_precedes_handler() {
    let (mut server, _tx, mut started) = fixture_with_config(
        "recovery",
        ServerConfig {
            request_admission_policy: RequestAdmissionPolicy {
                max_confirmed_in_flight: 2,
                confirmed_recovery_reserve: 1,
                ..Default::default()
            },
            dcc_password: Some("required".into()),
            ..Default::default()
        },
    )
    .await;
    dispatch(&server, request(0), source(0), None).await;
    observed(&mut started).await;
    for (id, service, data) in [
        (
            1,
            ConfirmedServiceChoice::DEVICE_COMMUNICATION_CONTROL,
            &[0x19, 1][..],
        ),
        (
            2,
            ConfirmedServiceChoice::DEVICE_COMMUNICATION_CONTROL,
            &[0x19, 2][..],
        ),
        (
            3,
            ConfirmedServiceChoice::DEVICE_COMMUNICATION_CONTROL,
            &[0x19][..],
        ),
        (
            4,
            ConfirmedServiceChoice::REINITIALIZE_DEVICE,
            &[0x09, 0][..],
        ),
    ] {
        let Apdu::ConfirmedRequest(mut req) = request(id) else {
            unreachable!()
        };
        req.service_choice = service;
        req.service_request = Bytes::copy_from_slice(data);
        dispatch(&server, Apdu::ConfirmedRequest(req), source(id), None).await;
        observed(&mut started).await;
        assert!(
            matches!(held_sends(&server).frames.lock().unwrap().last(), Some(Apdu::Abort(a)) if a.invoke_id == id)
        );
    }
    assert_eq!(
        server.request_admission_counters().recovery_admitted_total,
        0
    );
    dispatch(&server, enable(5, None), source(5), None).await;
    observed(&mut started).await;
    assert!(
        matches!(held_sends(&server).frames.lock().unwrap().last(), Some(Apdu::Error(e)) if e.error_code == ErrorCode::PASSWORD_FAILURE)
    );
    dispatch(&server, enable(6, Some("wrong")), source(6), None).await;
    observed(&mut started).await;
    assert!(
        matches!(held_sends(&server).frames.lock().unwrap().last(), Some(Apdu::Abort(a)) if a.invoke_id == 6)
    );
    assert_eq!(
        server
            .request_admission_counters()
            .recovery_overloaded_total,
        1
    );
    server.stop().await.unwrap();
}
