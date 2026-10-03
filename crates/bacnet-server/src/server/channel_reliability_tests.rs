//! A Channel's Reliability, on a running server: a FAILED distribution names
//! its first failure, a SUCCESSFUL one clears it, and a client simulates it
//! out of service (#1264, Clauses 12.53.8 to 12.53.10).
//!
//! These use the fixtures of `channel_wire_tests`: CH-1 writes AO-1 (REAL),
//! BO-1 (ENUMERATED), MSO-1 (three states) and CH-2's Channel_Number at
//! once; CH-3 writes AV-1 at once, AO-9 (missing) after 100 ms and AO-2 after
//! 200 ms. `start_ordered` sets up the Channels that pin which failure
//! Reliability names. Everything is read over the wire until the server
//! stops. The clock is paused.
use super::channel_wire_tests::{ch, channel, member, settled, start, write_channel, write_wire};
use super::command_action_wire_tests::{ao, outputs, read_db, read_wire, slot8};
use super::cov_wire_test_support::*;
use super::*;
use bacnet_objects::binary::BinaryOutputObject;
use bacnet_types::enums::{Reliability, WriteStatus};

const RELIABILITY: PropertyIdentifier = PropertyIdentifier::RELIABILITY;

/// CH-`instance`'s Reliability and whether Status_Flags shows FAULT.
async fn reliability(h: &mut Harness, instance: u32) -> (Reliability, bool) {
    let reliability = match read_wire(h, ch(instance), RELIABILITY, None).await.unwrap()[..] {
        [0x91, raw] => Reliability::from_raw(raw.into()),
        ref other => panic!("Reliability read {other:?}"),
    };
    let fault = match read_wire(h, ch(instance), SF, None).await.unwrap()[..] {
        [0x82, 0x04, flags] => flags & 0x40 != 0,
        ref other => panic!("Status_Flags read {other:?}"),
    };
    (reliability, fault)
}

async fn distribute(h: &mut Harness, instance: u32, value: PropertyValue) -> WriteStatus {
    write_channel(h, instance, &value, Some(8)).await.unwrap();
    settled(h, instance).await
}

#[tokio::test(start_paused = true)]
async fn channel_member_that_refuses_is_a_process_error_until_a_good_run_clears_it() {
    let mut h = start().await;
    assert_eq!(
        reliability(&mut h, 1).await,
        (Reliability::NO_FAULT_DETECTED, false)
    );
    // BO-1 refuses ENUMERATED 2 as out of range.
    let failed = distribute(&mut h, 1, PropertyValue::Unsigned(2)).await;
    assert_eq!(failed, WriteStatus::FAILED);
    assert_eq!(
        reliability(&mut h, 1).await,
        (Reliability::PROCESS_ERROR, true)
    );

    let cleared = distribute(&mut h, 1, PropertyValue::Real(1.0)).await;
    assert_eq!(cleared, WriteStatus::SUCCESSFUL);
    assert_eq!(
        reliability(&mut h, 1).await,
        (Reliability::NO_FAULT_DETECTED, false)
    );

    // A NULL that CH-2's Channel_Number refuses as the wrong datatype still
    // counts as written.
    let relinquished = distribute(&mut h, 1, PropertyValue::Null).await;
    assert_eq!(relinquished, WriteStatus::SUCCESSFUL);
    assert_eq!(
        reliability(&mut h, 1).await,
        (Reliability::NO_FAULT_DETECTED, false)
    );
}

#[tokio::test(start_paused = true)]
async fn channel_member_naming_a_missing_object_is_a_configuration_error() {
    let mut h = start().await;
    write_channel(&mut h, 3, &PropertyValue::Real(30.0), Some(10))
        .await
        .unwrap();
    // The verdict waits for the end of the distribution.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        reliability(&mut h, 3).await,
        (Reliability::NO_FAULT_DETECTED, false)
    );
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(settled(&mut h, 3).await, WriteStatus::FAILED);
    assert_eq!(
        reliability(&mut h, 3).await,
        (Reliability::CONFIGURATION_ERROR, true)
    );
}

#[tokio::test(start_paused = true)]
async fn channel_value_a_member_cannot_take_is_a_configuration_error() {
    let mut h = start().await;
    // A CharacterString coerces to none of CH-1's member datatypes, and the
    // first member that can't take it decides.
    let failed = distribute(&mut h, 1, PropertyValue::CharacterString("scene".into())).await;
    assert_eq!(failed, WriteStatus::FAILED);
    assert_eq!(
        reliability(&mut h, 1).await,
        (Reliability::CONFIGURATION_ERROR, true)
    );
    // FALSE coerces to state 0, which MSO-1 lacks: a refusal, not a
    // coercion failure.
    let refused = distribute(&mut h, 1, PropertyValue::Boolean(false)).await;
    assert_eq!(refused, WriteStatus::FAILED);
    assert_eq!(
        reliability(&mut h, 1).await,
        (Reliability::PROCESS_ERROR, true)
    );
}

#[tokio::test(start_paused = true)]
async fn channel_reliability_takes_a_client_value_only_out_of_service() {
    let mut h = start().await;
    let process_error = vec![0x91, Reliability::PROCESS_ERROR.to_raw() as u8];
    let refused = write_wire(
        &mut h,
        ch(1),
        RELIABILITY,
        None,
        process_error.clone(),
        None,
    )
    .await;
    assert_eq!(
        refused.unwrap_err().error_code,
        ErrorCode::WRITE_ACCESS_DENIED
    );
    let failed = distribute(&mut h, 1, PropertyValue::Unsigned(2)).await;
    assert_eq!(failed, WriteStatus::FAILED);

    let out_of_service = PropertyIdentifier::OUT_OF_SERVICE;
    write_wire(&mut h, ch(1), out_of_service, None, vec![0x11], None)
        .await
        .unwrap();
    let simulated = vec![0x91, Reliability::NO_FAULT_DETECTED.to_raw() as u8];
    write_wire(&mut h, ch(1), RELIABILITY, None, simulated, None)
        .await
        .unwrap();
    assert_eq!(
        reliability(&mut h, 1).await,
        (Reliability::NO_FAULT_DETECTED, false)
    );
    // Back in service, the last distribution's verdict shows again.
    write_wire(&mut h, ch(1), out_of_service, None, vec![0x10], None)
        .await
        .unwrap();
    assert_eq!(
        reliability(&mut h, 1).await,
        (Reliability::PROCESS_ERROR, true)
    );
}

/// A server with AO-1, AO-2 and BO-1, and three Channels whose members fail
/// differently: AO-9 is missing (CONFIGURATION_ERROR) and BO-1 refuses
/// ENUMERATED 2 (PROCESS_ERROR). CH-4 writes AO-9 then BO-1, CH-5 BO-1 then
/// AO-9, both at once; CH-6 writes AO-9 at once and AO-2 after a second.
async fn start_ordered() -> Harness {
    let bo1 = ObjectIdentifier::new(ObjectType::BINARY_OUTPUT, 1).unwrap();
    let ao9 = member(ao(9), PV);
    Harness::start_with(ServerConfig::default(), move |db| {
        outputs(db);
        db.add(Box::new(BinaryOutputObject::new(1, "BO-1").unwrap()))
            .unwrap();
        let bo1 = member(bo1, PV);
        let channels = [
            (4, vec![(ao9.clone(), 0), (bo1.clone(), 0)]),
            (5, vec![(bo1, 0), (ao9.clone(), 0)]),
            (6, vec![(ao9, 0), (member(ao(2), PV), 1000)]),
        ];
        for (instance, members) in channels {
            db.add(Box::new(channel(instance, 30, members))).unwrap();
        }
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn channel_reliability_names_the_first_failure_in_write_order() {
    let mut h = start_ordered().await;
    for (instance, first) in [
        (4, Reliability::CONFIGURATION_ERROR),
        (5, Reliability::PROCESS_ERROR),
    ] {
        let failed = distribute(&mut h, instance, PropertyValue::Unsigned(2)).await;
        assert_eq!(failed, WriteStatus::FAILED);
        assert_eq!(reliability(&mut h, instance).await, (first, true));
    }
}

#[tokio::test(start_paused = true)]
async fn stop_after_a_member_failed_keeps_that_failure() {
    let mut h = start_ordered().await;
    write_channel(&mut h, 6, &PropertyValue::Real(5.0), Some(8))
        .await
        .unwrap();
    // AO-9 has failed; AO-2 waits out its second when the server stops.
    tokio::time::sleep(Duration::from_millis(500)).await;
    h.server.stop().await.unwrap();
    assert_eq!(
        read_db(&h, ch(6), PropertyIdentifier::WRITE_STATUS, None).await,
        PropertyValue::Enumerated(WriteStatus::FAILED.to_raw())
    );
    assert_eq!(
        read_db(&h, ch(6), RELIABILITY, None).await,
        PropertyValue::Enumerated(Reliability::CONFIGURATION_ERROR.to_raw())
    );
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Null);
}
