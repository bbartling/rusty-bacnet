//! A Channel member in another device is written there as a confirmed
//! WriteProperty, and how that write ends decides Write_Status and
//! Reliability (#1264, Clauses 12.53.7, 12.53.9 and 12.53.11).
//!
//! Devices 9 and 11 are bound to the harness peer; Device 10 has no binding.
//! CH-5 (channel 21, group 27) writes AO-1 in Device 9 at once and the local
//! AO-2 100 ms after the distribution starts. CH-6 writes AO-1 in Device 10.
//! CH-7 writes, in this order and all at once, AO-1 and AO-3 in Device 9,
//! AO-4 in Device 11 and the local AO-2. Requests are taken from the frames
//! the server sends and answered by hand. The clock is paused, and the
//! server's APDU timeout is the default 3 seconds.
use super::channel_wire_tests::{ch, channel, member, settled, write_channel, write_status};
use super::command_action_wire_tests::{ao, outputs, read_db, read_wire, slot8};
use super::command_remote_write_tests::{
    ack, device, disable_initiation, remote_write, sent_writes,
};
use super::cov_wire_test_support::*;
use super::*;
use bacnet_encoding::npdu::{encode_npdu, Npdu};
use bacnet_services::write_group::{GroupChannelValue, WriteGroupRequest};
use bacnet_services::write_property::WritePropertyRequest;
use bacnet_transport::port::{ReceivedNpdu, TransportProvenance};
use bacnet_types::constructed::BACnetDeviceObjectPropertyReference;
use bacnet_types::enums::{Reliability, WriteStatus};

/// AO-1's Present_Value in Device `instance`.
fn remote_member(instance: u32) -> BACnetDeviceObjectPropertyReference {
    remote_output(instance, 1)
}

/// AO-`output`'s Present_Value in Device `instance`.
fn remote_output(instance: u32, output: u32) -> BACnetDeviceObjectPropertyReference {
    BACnetDeviceObjectPropertyReference {
        device_identifier: Some(device(instance)),
        ..member(ao(output), PV)
    }
}

async fn start() -> Harness {
    let h = Harness::start_with(ServerConfig::default(), |db| {
        outputs(db);
        let mut five = channel(5, 21, vec![(remote_member(9), 0), (member(ao(2), PV), 100)]);
        five.set_control_groups(vec![27]).unwrap();
        db.add(Box::new(five)).unwrap();
        db.add(Box::new(channel(6, 22, vec![(remote_member(10), 0)])))
            .unwrap();
        let seven = vec![
            (remote_output(9, 1), 0),
            (remote_output(9, 3), 0),
            (remote_output(11, 4), 0),
            (member(ao(2), PV), 0),
        ];
        db.add(Box::new(channel(7, 23, seven))).unwrap();
    })
    .await;
    for instance in [9, 11] {
        let binding = DeviceBinding::local(device(instance), PEER).unwrap();
        h.server
            .device_bindings
            .write()
            .await
            .insert_configured(binding, |_| false)
            .unwrap();
    }
    h
}

/// CH-`instance`'s Reliability, read over the wire.
async fn reliability(h: &mut Harness, instance: u32) -> Reliability {
    match read_wire(h, ch(instance), PropertyIdentifier::RELIABILITY, None)
        .await
        .unwrap()[..]
    {
        [0x91, raw] => Reliability::from_raw(raw.into()),
        ref other => panic!("Reliability read {other:?}"),
    }
}

/// Whether CH-`instance`'s Status_Flags show FAULT, read over the wire.
async fn fault(h: &mut Harness, instance: u32) -> bool {
    match read_wire(h, ch(instance), SF, None).await.unwrap()[..] {
        [0x82, 0x04, flags] => flags & 0x40 != 0,
        ref other => panic!("Status_Flags read {other:?}"),
    }
}

/// Wait for the one WriteProperty sent next, check it writes `object`, and
/// return its invoke ID and value.
async fn next_request(h: &Harness, object: ObjectIdentifier) -> (u8, Vec<u8>) {
    let sent = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let sent = sent_writes(h);
            if !sent.is_empty() {
                return sent;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("a WriteProperty to another device");
    let [(invoke_id, request)]: [(u8, WritePropertyRequest); 1] = sent.try_into().unwrap();
    assert_eq!(request.object_identifier, object);
    (invoke_id, request.property_value)
}

/// Hand the server a WriteGroup for group 27 at priority 8 giving channel
/// 21 `value`, as a local broadcast.
async fn write_group(h: &Harness, value: &PropertyValue) {
    let mut encoded = BytesMut::new();
    encode_property_value(&mut encoded, value).unwrap();
    let mut service = BytesMut::new();
    WriteGroupRequest {
        group_number: std::num::NonZeroU32::new(27).unwrap(),
        write_priority: 8,
        change_list: vec![GroupChannelValue {
            channel: 21,
            override_priority: None,
            value: encoded.to_vec(),
        }],
        inhibit_delay: None,
    }
    .encode(&mut service)
    .unwrap();
    let mut apdu = BytesMut::new();
    encode_apdu(
        &mut apdu,
        &Apdu::UnconfirmedRequest(UnconfirmedRequestPdu {
            service_choice: UnconfirmedServiceChoice::WRITE_GROUP,
            service_request: service.freeze(),
        }),
    )
    .unwrap();
    let mut npdu = BytesMut::new();
    let payload = apdu.freeze();
    encode_npdu(
        &mut npdu,
        &Npdu {
            payload,
            ..Npdu::default()
        },
    )
    .unwrap();
    h.tx.send(ReceivedNpdu {
        direct_response: None,
        npdu: npdu.freeze(),
        source_mac: MacAddr::from_slice(&PEER),
        link_layer_group: true,
        data_attributes: Vec::new(),
        provenance: TransportProvenance::unverified(),
        reply_tx: None,
    })
    .await
    .unwrap();
}

/// A device's answer to the request with this invoke ID.
type Answer = fn(u8) -> Apdu;

fn error(invoke_id: u8, error_code: ErrorCode) -> Apdu {
    Apdu::Error(ErrorPdu {
        invoke_id,
        service_choice: ConfirmedServiceChoice::WRITE_PROPERTY,
        error_class: ErrorClass::PROPERTY,
        error_code,
        error_data: Bytes::new(),
    })
}

fn reject(invoke_id: u8, reject_reason: RejectReason) -> Apdu {
    Apdu::Reject(RejectPdu {
        invoke_id,
        reject_reason,
    })
}

#[tokio::test(start_paused = true)]
async fn channel_writes_a_member_in_another_device_and_waits_for_its_answer() {
    let mut h = start().await;
    write_channel(&mut h, 5, &PropertyValue::Real(80.0), Some(8))
        .await
        .unwrap();
    // Device 9 gets the value as written, at the written priority.
    let invoke_id = remote_write(&h).await;
    assert_eq!(write_status(&mut h, 5).await, WriteStatus::IN_PROGRESS);
    let busy = write_channel(&mut h, 5, &PropertyValue::Real(1.0), Some(8)).await;
    assert_eq!(busy.unwrap_err().error_code, ErrorCode::BUSY);

    // AO-2's 100 ms pass while the write is outstanding: the member is
    // written once the answer comes, not before.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Null);
    assert_eq!(h.server.notification_transactions.active_count(), 1);
    h.respond(ack(invoke_id)).await;
    assert_eq!(settled(&mut h, 5).await, WriteStatus::SUCCESSFUL);
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Real(80.0));
    assert_eq!(reliability(&mut h, 5).await, Reliability::NO_FAULT_DETECTED);
    assert_eq!(h.server.notification_transactions.active_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn channel_member_in_another_device_that_refuses_fails_the_distribution() {
    let mut h = start().await;
    let answers: [(Answer, Reliability); 4] = [
        (
            |id| error(id, ErrorCode::WRITE_ACCESS_DENIED),
            Reliability::PROCESS_ERROR,
        ),
        (
            |id| {
                Apdu::Abort(AbortPdu {
                    sent_by_server: true,
                    invoke_id: id,
                    abort_reason: AbortReason::OTHER,
                })
            },
            Reliability::PROCESS_ERROR,
        ),
        // The answer says the member names nothing there, or a property that
        // takes no REAL: the member list is at fault.
        (
            |id| error(id, ErrorCode::UNKNOWN_OBJECT),
            Reliability::CONFIGURATION_ERROR,
        ),
        (
            |id| reject(id, RejectReason::INVALID_PARAMETER_DATA_TYPE),
            Reliability::CONFIGURATION_ERROR,
        ),
    ];
    for (answer, expected) in answers {
        write_channel(&mut h, 5, &PropertyValue::Real(80.0), Some(8))
            .await
            .unwrap();
        let invoke_id = remote_write(&h).await;
        h.respond(answer(invoke_id)).await;
        // The refusal is final: no retry, and the local member still goes.
        assert_eq!(settled(&mut h, 5).await, WriteStatus::FAILED);
        assert_eq!(reliability(&mut h, 5).await, expected);
        assert!(fault(&mut h, 5).await);
        assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Real(80.0));
        assert!(sent_writes(&h).is_empty());
    }

    // The next distribution that succeeds clears the fault.
    write_channel(&mut h, 5, &PropertyValue::Real(70.0), Some(8))
        .await
        .unwrap();
    let (invoke_id, _) = next_request(&h, ao(1)).await;
    h.respond(ack(invoke_id)).await;
    assert_eq!(settled(&mut h, 5).await, WriteStatus::SUCCESSFUL);
    assert_eq!(reliability(&mut h, 5).await, Reliability::NO_FAULT_DETECTED);
    assert!(!fault(&mut h, 5).await);
}

#[tokio::test(start_paused = true)]
async fn channel_null_a_member_in_another_device_refuses_as_the_wrong_datatype_succeeds() {
    let mut h = start().await;
    // Clause 12.53.7 names an Error of INVALID_DATATYPE and a Reject of
    // INVALID_PARAMETER_DATA_TYPE; both arrive with their payload (#1323).
    let answers: [fn(u8) -> Apdu; 2] = [
        |id| error(id, ErrorCode::INVALID_DATA_TYPE),
        |id| reject(id, RejectReason::INVALID_PARAMETER_DATA_TYPE),
    ];
    for answer in answers {
        write_channel(&mut h, 5, &PropertyValue::Null, Some(8))
            .await
            .unwrap();
        let (invoke_id, value) = next_request(&h, ao(1)).await;
        assert_eq!(value, [0x00]);
        h.respond(answer(invoke_id)).await;
        assert_eq!(settled(&mut h, 5).await, WriteStatus::SUCCESSFUL);
        assert_eq!(reliability(&mut h, 5).await, Reliability::NO_FAULT_DETECTED);
    }

    // Any other refusal of a NULL still fails.
    write_channel(&mut h, 5, &PropertyValue::Null, Some(8))
        .await
        .unwrap();
    let (invoke_id, _) = next_request(&h, ao(1)).await;
    h.respond(error(invoke_id, ErrorCode::WRITE_ACCESS_DENIED))
        .await;
    assert_eq!(settled(&mut h, 5).await, WriteStatus::FAILED);
    assert_eq!(reliability(&mut h, 5).await, Reliability::PROCESS_ERROR);
}

#[tokio::test(start_paused = true)]
async fn channel_member_in_another_device_that_never_answers_is_a_communication_failure() {
    let mut h = start().await;
    write_channel(&mut h, 5, &PropertyValue::Real(80.0), Some(8))
        .await
        .unwrap();
    let invoke_id = remote_write(&h).await;
    // Each silent attempt waits 3 seconds; three retries follow the first,
    // all under the one invoke ID.
    tokio::time::sleep(Duration::from_millis(11_900)).await;
    let retries = sent_writes(&h);
    assert_eq!(retries.len(), 3);
    assert!(retries.iter().all(|(id, _)| *id == invoke_id));
    assert_eq!(write_status(&mut h, 5).await, WriteStatus::IN_PROGRESS);

    // The local member still goes, and its success doesn't hide the failure.
    assert_eq!(settled(&mut h, 5).await, WriteStatus::FAILED);
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Real(80.0));
    assert_eq!(
        reliability(&mut h, 5).await,
        Reliability::COMMUNICATION_FAILURE
    );
    assert_eq!(h.server.notification_transactions.active_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn channel_skips_the_rest_of_a_silent_device_for_the_distribution() {
    let mut h = start().await;
    let started = tokio::time::Instant::now();
    write_channel(&mut h, 7, &PropertyValue::Real(80.0), Some(8))
        .await
        .unwrap();
    // AO-1's write to Device 9 goes four times under one invoke ID, with no
    // answer.
    tokio::time::sleep(Duration::from_millis(11_900)).await;
    let attempts = sent_writes(&h);
    assert_eq!(attempts.len(), 4);
    assert!(attempts
        .iter()
        .all(|(id, request)| *id == attempts[0].0 && request.object_identifier == ao(1)));

    // AO-3 shares the silent device, so it fails unsent; Device 11 still
    // gets AO-4, and the local AO-2 is written.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (invoke_id, _) = next_request(&h, ao(4)).await;
    h.respond(ack(invoke_id)).await;
    assert_eq!(settled(&mut h, 7).await, WriteStatus::FAILED);
    assert!(started.elapsed() < Duration::from_millis(12_500));
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Real(80.0));
    assert_eq!(
        reliability(&mut h, 7).await,
        Reliability::COMMUNICATION_FAILURE
    );
    assert!(sent_writes(&h).is_empty());

    // The next distribution tries Device 9 again.
    write_channel(&mut h, 7, &PropertyValue::Real(70.0), Some(8))
        .await
        .unwrap();
    for output in [1, 3, 4] {
        let (invoke_id, _) = next_request(&h, ao(output)).await;
        h.respond(ack(invoke_id)).await;
    }
    assert_eq!(settled(&mut h, 7).await, WriteStatus::SUCCESSFUL);
    assert_eq!(reliability(&mut h, 7).await, Reliability::NO_FAULT_DETECTED);
}

#[tokio::test(start_paused = true)]
async fn channel_member_in_another_device_sends_nothing_without_initiation_or_a_binding() {
    let mut h = start().await;
    // Device 10 has no binding: nothing is sent.
    write_channel(&mut h, 6, &PropertyValue::Real(80.0), Some(8))
        .await
        .unwrap();
    assert_eq!(settled(&mut h, 6).await, WriteStatus::FAILED);
    assert_eq!(
        reliability(&mut h, 6).await,
        Reliability::COMMUNICATION_FAILURE
    );

    // DCC restricts initiation: Device 9 gets no frame either.
    disable_initiation(&h);
    write_channel(&mut h, 5, &PropertyValue::Real(80.0), Some(8))
        .await
        .unwrap();
    assert_eq!(settled(&mut h, 5).await, WriteStatus::FAILED);
    assert_eq!(
        reliability(&mut h, 5).await,
        Reliability::COMMUNICATION_FAILURE
    );
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Real(80.0));
    assert!(sent_writes(&h).is_empty());
}

#[tokio::test(start_paused = true)]
async fn stop_during_an_outstanding_member_write_ends_the_distribution_failed() {
    let mut h = start().await;
    write_channel(&mut h, 5, &PropertyValue::Real(80.0), Some(8))
        .await
        .unwrap();
    remote_write(&h).await;
    assert_eq!(h.server.notification_transactions.active_count(), 1);

    h.server.stop().await.unwrap();
    let status = read_db(&h, ch(5), PropertyIdentifier::WRITE_STATUS, None).await;
    assert_eq!(
        status,
        PropertyValue::Enumerated(WriteStatus::FAILED.to_raw())
    );
    let reliability = read_db(&h, ch(5), PropertyIdentifier::RELIABILITY, None).await;
    assert_eq!(
        reliability,
        PropertyValue::Enumerated(Reliability::PROCESS_ERROR.to_raw())
    );
    // The invoke ID is free, and the member after it was never written.
    assert_eq!(h.server.notification_transactions.active_count(), 0);
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Null);
}

#[tokio::test(start_paused = true)]
async fn write_group_distribution_writes_a_member_in_another_device() {
    let mut h = start().await;
    write_group(&h, &PropertyValue::Real(80.0)).await;
    let invoke_id = remote_write(&h).await;
    h.respond(ack(invoke_id)).await;
    assert_eq!(settled(&mut h, 5).await, WriteStatus::SUCCESSFUL);
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Real(80.0));
    assert_eq!(reliability(&mut h, 5).await, Reliability::NO_FAULT_DETECTED);
}
