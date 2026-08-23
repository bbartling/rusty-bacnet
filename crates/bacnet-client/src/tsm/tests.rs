use super::*;

#[test]
fn allocate_invoke_id_sequential() {
    let mut tsm = Tsm::new(TsmConfig::default());
    let mac = [127, 0, 0, 1, 0xBA, 0xC0];
    let id1 = tsm.allocate_invoke_id(&mac);
    let id2 = tsm.allocate_invoke_id(&mac);
    assert_eq!(id1, Some(0));
    assert_eq!(id2, Some(1));
}

#[test]
fn allocate_invoke_id_per_destination() {
    let mut tsm = Tsm::new(TsmConfig::default());
    let mac_a = [10, 0, 0, 1, 0xBA, 0xC0];
    let mac_b = [10, 0, 0, 2, 0xBA, 0xC0];
    let id_a = tsm.allocate_invoke_id(&mac_a);
    let id_b = tsm.allocate_invoke_id(&mac_b);
    assert_eq!(id_a, Some(0));
    assert_eq!(id_b, Some(0));
}

#[test]
fn allocate_invoke_id_wraps() {
    let mut tsm = Tsm::new(TsmConfig::default());
    let mac = [127, 0, 0, 1, 0xBA, 0xC0];
    for i in 0..256 {
        assert_eq!(tsm.allocate_invoke_id(&mac), Some(i as u8));
    }
    assert_eq!(tsm.allocate_invoke_id(&mac), None);
}

#[test]
fn release_makes_id_available() {
    let mut tsm = Tsm::new(TsmConfig::default());
    let mac = [127, 0, 0, 1, 0xBA, 0xC0];
    let id0 = tsm.allocate_invoke_id(&mac).unwrap();
    let id1 = tsm.allocate_invoke_id(&mac).unwrap();
    assert_eq!(id0, 0);
    assert_eq!(id1, 1);
    tsm.release_invoke_id(&mac, id0);
    let id2 = tsm.allocate_invoke_id(&mac).unwrap();
    assert_eq!(id2, 2);
    tsm.release_invoke_id(&mac, id1);
    tsm.release_invoke_id(&mac, id2);
    let id3 = tsm.allocate_invoke_id(&mac).unwrap();
    assert_eq!(id3, 0);
}

#[tokio::test]
async fn register_and_complete_transaction() {
    let mut tsm = Tsm::new(TsmConfig::default());
    let mac = MacAddr::from_slice(&[127, 0, 0, 1, 0xBA, 0xC0]);
    let invoke_id = tsm.allocate_invoke_id(&mac).unwrap();
    let rx = tsm.register_transaction(
        mac.clone(),
        invoke_id,
        ConfirmedServiceChoice::READ_PROPERTY,
    );
    let response = TsmResponse::ComplexAck {
        service_data: Bytes::from_static(&[0xDE, 0xAD]),
    };
    let outcome = tsm.complete_transaction(
        &mac,
        invoke_id,
        Some(ConfirmedServiceChoice::READ_PROPERTY),
        response,
    );
    assert_eq!(outcome, CompletionOutcome::Delivered);
    match rx.await.unwrap() {
        TsmResponse::ComplexAck { service_data } => assert_eq!(service_data, vec![0xDE, 0xAD]),
        _ => panic!("Expected ComplexAck"),
    }
}

#[tokio::test]
async fn mismatched_service_choice_leaves_the_transaction_pending() {
    let mut tsm = Tsm::new(TsmConfig::default());
    let mac = MacAddr::from_slice(&[127, 0, 0, 1, 0xBA, 0xC0]);
    let invoke_id = tsm.allocate_invoke_id(&mac).unwrap();
    let rx = tsm.register_transaction(
        mac.clone(),
        invoke_id,
        ConfirmedServiceChoice::READ_PROPERTY,
    );
    let outcome = tsm.complete_transaction(
        &mac,
        invoke_id,
        Some(ConfirmedServiceChoice::WRITE_PROPERTY),
        TsmResponse::ComplexAck {
            service_data: Bytes::from_static(&[0xBA, 0xD0]),
        },
    );
    assert_eq!(
        outcome,
        CompletionOutcome::ServiceChoiceMismatch {
            expected: ConfirmedServiceChoice::READ_PROPERTY,
            observed: ConfirmedServiceChoice::WRITE_PROPERTY,
        }
    );
    assert_eq!(tsm.pending_count(), 1, "transaction must stay pending");
    assert_eq!(
        tsm.allocate_invoke_id(&mac),
        Some(invoke_id.wrapping_add(1)),
        "the invoke ID must not have been handed back for reuse"
    );
    let outcome = tsm.complete_transaction(
        &mac,
        invoke_id,
        Some(ConfirmedServiceChoice::READ_PROPERTY),
        TsmResponse::ComplexAck {
            service_data: Bytes::from_static(&[0xDE, 0xAD]),
        },
    );
    assert_eq!(outcome, CompletionOutcome::Delivered);
    match rx.await.unwrap() {
        TsmResponse::ComplexAck { service_data } => {
            assert_eq!(service_data.as_ref(), &[0xDE, 0xAD]);
        }
        other => panic!("expected ComplexAck, got {other:?}"),
    }
}

#[tokio::test]
async fn a_response_without_a_service_choice_completes_any_transaction() {
    let mut tsm = Tsm::new(TsmConfig::default());
    let mac = MacAddr::from_slice(&[127, 0, 0, 1, 0xBA, 0xC0]);
    let invoke_id = tsm.allocate_invoke_id(&mac).unwrap();
    let rx = tsm.register_transaction(
        mac.clone(),
        invoke_id,
        ConfirmedServiceChoice::READ_PROPERTY,
    );
    let outcome =
        tsm.complete_transaction(&mac, invoke_id, None, TsmResponse::Reject { reason: 9 });
    assert_eq!(outcome, CompletionOutcome::Delivered);
    assert!(matches!(
        rx.await.unwrap(),
        TsmResponse::Reject { reason: 9 }
    ));
}

#[tokio::test]
async fn complete_unknown_transaction_reports_no_transaction() {
    let mut tsm = Tsm::new(TsmConfig::default());
    let mac = MacAddr::from_slice(&[127, 0, 0, 1, 0xBA, 0xC0]);
    let outcome = tsm.complete_transaction(
        &mac,
        42,
        Some(ConfirmedServiceChoice::READ_PROPERTY),
        TsmResponse::SimpleAck,
    );
    assert_eq!(outcome, CompletionOutcome::NoTransaction);
}

#[test]
fn cancel_transaction() {
    let mut tsm = Tsm::new(TsmConfig::default());
    let mac = MacAddr::from_slice(&[127, 0, 0, 1, 0xBA, 0xC0]);
    let invoke_id = tsm.allocate_invoke_id(&mac).unwrap();
    let _rx = tsm.register_transaction(
        mac.clone(),
        invoke_id,
        ConfirmedServiceChoice::READ_PROPERTY,
    );
    assert_eq!(tsm.pending_count(), 1);
    assert!(tsm.cancel_transaction(&mac, invoke_id));
    assert_eq!(tsm.pending_count(), 0);
}

#[test]
fn segmented_admission_and_request_timeout_are_serialized() {
    let mac = MacAddr::from_slice(&[127, 0, 0, 1, 0xBA, 0xC0]);
    let mut admitted_first = Tsm::new(TsmConfig::default());
    let invoke_id = admitted_first.allocate_invoke_id(&mac).unwrap();
    let registration = admitted_first.register_transaction_with_progress(
        mac.clone(),
        invoke_id,
        ConfirmedServiceChoice::READ_PROPERTY,
    );
    let generation = admitted_first
        .begin_segmented_response(&mac, invoke_id, &registration.owner)
        .unwrap();
    assert_eq!(
        *registration.progress.borrow(),
        TransactionProgress::SegmentedResponse { generation }
    );
    assert_eq!(
        admitted_first.expire_request_timer(&mac, invoke_id, &registration.owner, true),
        RequestTimerExpiration::SegmentedResponse { generation }
    );
    assert_eq!(admitted_first.pending_count(), 1);

    let mut timeout_first = Tsm::new(TsmConfig::default());
    let invoke_id = timeout_first.allocate_invoke_id(&mac).unwrap();
    let registration = timeout_first.register_transaction_with_progress(
        mac.clone(),
        invoke_id,
        ConfirmedServiceChoice::READ_PROPERTY,
    );
    assert_eq!(
        timeout_first.expire_request_timer(&mac, invoke_id, &registration.owner, true),
        RequestTimerExpiration::TimedOut
    );
    assert_eq!(
        timeout_first.begin_segmented_response(&mac, invoke_id, &registration.owner),
        None
    );
    assert_eq!(timeout_first.pending_count(), 0);
}

#[test]
fn retry_send_failure_recheck_preserves_later_segmented_admission() {
    let mut tsm = Tsm::new(TsmConfig::default());
    let mac = MacAddr::from_slice(&[127, 0, 0, 1, 0xBA, 0xC0]);
    let invoke_id = tsm.allocate_invoke_id(&mac).unwrap();
    let registration = tsm.register_transaction_with_progress(
        mac.clone(),
        invoke_id,
        ConfirmedServiceChoice::READ_PROPERTY,
    );
    assert_eq!(
        tsm.expire_request_timer(&mac, invoke_id, &registration.owner, false),
        RequestTimerExpiration::Retry
    );
    let generation = tsm
        .begin_segmented_response(&mac, invoke_id, &registration.owner)
        .unwrap();
    assert_eq!(
        tsm.expire_request_timer(&mac, invoke_id, &registration.owner, true),
        RequestTimerExpiration::SegmentedResponse { generation }
    );
    assert_eq!(tsm.pending_count(), 1);
}

#[test]
fn stale_segment_timer_generation_cannot_cancel_new_activity() {
    let mut tsm = Tsm::new(TsmConfig::default());
    let mac = MacAddr::from_slice(&[127, 0, 0, 1, 0xBA, 0xC0]);
    let invoke_id = tsm.allocate_invoke_id(&mac).unwrap();
    let registration = tsm.register_transaction_with_progress(
        mac.clone(),
        invoke_id,
        ConfirmedServiceChoice::READ_PROPERTY,
    );
    let stale_generation = tsm
        .begin_segmented_response(&mac, invoke_id, &registration.owner)
        .unwrap();
    let current_generation = tsm
        .record_segmented_response_activity(&mac, invoke_id, &registration.owner)
        .unwrap();
    assert_ne!(stale_generation, current_generation);
    assert_eq!(
        tsm.expire_segment_timer(&mac, invoke_id, &registration.owner, stale_generation),
        SegmentTimerExpiration::Activity {
            generation: current_generation
        }
    );
    assert_eq!(tsm.pending_count(), 1);
    assert_eq!(
        *registration.progress.borrow(),
        TransactionProgress::SegmentedResponse {
            generation: current_generation
        }
    );
    assert_eq!(
        tsm.expire_segment_timer(&mac, invoke_id, &registration.owner, current_generation),
        SegmentTimerExpiration::TimedOut
    );
    assert_eq!(tsm.pending_count(), 0);
    assert_eq!(tsm.allocate_invoke_id(&mac), Some(0));
}

#[tokio::test]
async fn stale_owner_cannot_mutate_reused_transaction_key() {
    let mut tsm = Tsm::new(TsmConfig::default());
    let mac = MacAddr::from_slice(&[127, 0, 0, 1, 0xBA, 0xC0]);
    let invoke_id = tsm.allocate_invoke_id(&mac).unwrap();
    let first = tsm.register_transaction_with_progress(
        mac.clone(),
        invoke_id,
        ConfirmedServiceChoice::READ_PROPERTY,
    );
    assert!(tsm.cancel_transaction_for_owner(&mac, invoke_id, &first.owner));
    assert_eq!(tsm.allocate_invoke_id(&mac), Some(invoke_id));
    let replacement = tsm.register_transaction_with_progress(
        mac.clone(),
        invoke_id,
        ConfirmedServiceChoice::READ_PROPERTY,
    );
    let generation = tsm
        .begin_segmented_response(&mac, invoke_id, &replacement.owner)
        .unwrap();
    assert_eq!(
        tsm.expire_request_timer(&mac, invoke_id, &first.owner, true),
        RequestTimerExpiration::NoTransaction
    );
    assert_eq!(
        tsm.expire_segment_timer(&mac, invoke_id, &first.owner, generation),
        SegmentTimerExpiration::NoTransaction
    );
    assert!(!tsm.cancel_transaction_for_owner(&mac, invoke_id, &first.owner));
    assert_eq!(
        tsm.begin_segmented_response(&mac, invoke_id, &first.owner),
        None
    );
    assert_eq!(
        tsm.record_segmented_response_activity(&mac, invoke_id, &first.owner),
        None
    );
    assert!(!tsm.reset_segmented_response(&mac, invoke_id, &first.owner));
    assert_eq!(
        tsm.complete_transaction_for_owner(
            &mac,
            invoke_id,
            &first.owner,
            Some(ConfirmedServiceChoice::READ_PROPERTY),
            TsmResponse::SimpleAck,
        ),
        CompletionOutcome::NoTransaction
    );
    assert_eq!(tsm.pending_count(), 1);
    assert_eq!(
        *replacement.progress.borrow(),
        TransactionProgress::SegmentedResponse { generation }
    );
    assert_eq!(
        tsm.complete_transaction_for_owner(
            &mac,
            invoke_id,
            &replacement.owner,
            Some(ConfirmedServiceChoice::READ_PROPERTY),
            TsmResponse::SimpleAck,
        ),
        CompletionOutcome::Delivered
    );
    assert!(matches!(
        replacement.response.await.unwrap(),
        TsmResponse::SimpleAck
    ));
}
