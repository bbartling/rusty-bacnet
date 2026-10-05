//! A Channel learns the datatype of a member in another device with a
//! ReadProperty, coerces its value to it (Table 12-63) and keeps it until the
//! member is replaced; a read that fails leaves the value as written (#1342).
//!
//! CH-9 (channel 25) writes BO-1's Present_Value in Device 9, bound to the
//! harness peer, at once. The read and the write are answered by hand. The
//! clock is paused, and the server's APDU timeout is the default 3 seconds.
use super::channel_remote_write_tests::{
    answer_reads, error, next_reads, next_request, read_ack, reliability, sent_reads, start_with,
};
use super::channel_wire_tests::{ch, channel, settled, write_channel, write_wire};
use super::command_remote_write_tests::{ack, device, sent_writes};
use super::cov_wire_test_support::*;
use super::*;
use bacnet_encoding::constructed::encode_device_object_property_reference;
use bacnet_types::constructed::BACnetDeviceObjectPropertyReference;
use bacnet_types::enums::{Reliability, WriteStatus};

fn bo1() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::BINARY_OUTPUT, 1).unwrap()
}

/// BO-1's Present_Value in Device 9.
fn remote_bo1() -> BACnetDeviceObjectPropertyReference {
    BACnetDeviceObjectPropertyReference {
        device_identifier: Some(device(9)),
        ..BACnetDeviceObjectPropertyReference::new_local(bo1(), PV.to_raw())
    }
}

async fn start() -> Harness {
    start_with(|db| {
        db.add(Box::new(channel(9, 25, vec![(remote_bo1(), 0)])))
            .unwrap();
    })
    .await
}

const ACTIVE: [u8; 2] = [0x91, 0x01];
const INACTIVE: [u8; 2] = [0x91, 0x00];

/// REAL `value`, application-tagged.
fn real_octets(value: f32) -> Vec<u8> {
    let mut octets = vec![0x44];
    octets.extend_from_slice(&value.to_be_bytes());
    octets
}

/// Distribute `value` from CH-9, answer the write it makes to BO-1 with
/// `answer`, and return the value written and Write_Status.
async fn distribute(
    h: &mut Harness,
    value: f32,
    read_answer: Option<&PropertyValue>,
    answer: fn(u8) -> Apdu,
) -> (Vec<u8>, WriteStatus) {
    write_channel(h, 9, &PropertyValue::Real(value), Some(8))
        .await
        .unwrap();
    if let Some(present) = read_answer {
        answer_reads(h, 1, present).await;
    }
    let (invoke_id, written) = next_request(h, bo1()).await;
    h.respond(answer(invoke_id)).await;
    (written, settled(h, 9).await)
}

#[tokio::test(start_paused = true)]
async fn channel_coerces_a_value_to_the_datatype_a_member_in_another_device_reads_as() {
    let mut h = start().await;
    // BO-1's Present_Value reads as an ENUMERATED, so REAL 1.0 goes as
    // ACTIVE (Coercion Rule 5).
    let inactive = PropertyValue::Enumerated(0);
    let (written, status) = distribute(&mut h, 1.0, Some(&inactive), ack).await;
    assert_eq!(
        (written, status),
        (ACTIVE.to_vec(), WriteStatus::SUCCESSFUL)
    );

    // The datatype is kept: the next distribution sends no read.
    let (written, status) = distribute(&mut h, 0.0, None, ack).await;
    assert_eq!(
        (written, status),
        (INACTIVE.to_vec(), WriteStatus::SUCCESSFUL)
    );
    assert!(sent_reads(&h).is_empty());

    // Writing the member, even to the same reference, forgets it.
    let mut reference = BytesMut::new();
    encode_device_object_property_reference(&mut reference, &remote_bo1());
    let list = PropertyIdentifier::LIST_OF_OBJECT_PROPERTY_REFERENCES;
    write_wire(&mut h, ch(9), list, Some(1), reference.to_vec(), None)
        .await
        .unwrap();
    let (written, status) = distribute(&mut h, 1.0, Some(&inactive), ack).await;
    assert_eq!(
        (written, status),
        (ACTIVE.to_vec(), WriteStatus::SUCCESSFUL)
    );
    assert_eq!(h.server.notification_transactions.active_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn channel_sends_its_value_as_written_when_the_member_read_tells_no_datatype() {
    let mut h = start().await;
    // A refused read: the REAL goes as written, and BO-1 refuses it.
    write_channel(&mut h, 9, &PropertyValue::Real(1.0), Some(8))
        .await
        .unwrap();
    let [(invoke_id, request)]: [_; 1] = next_reads(&h, 1).await.try_into().unwrap();
    assert_eq!(request.object_identifier, bo1());
    h.respond(Apdu::Error(ErrorPdu {
        invoke_id,
        service_choice: ConfirmedServiceChoice::READ_PROPERTY,
        error_class: ErrorClass::PROPERTY,
        error_code: ErrorCode::READ_ACCESS_DENIED,
        error_data: Bytes::new(),
    }))
    .await;
    let (invoke_id, written) = next_request(&h, bo1()).await;
    assert_eq!(written, real_octets(1.0));
    h.respond(error(invoke_id, ErrorCode::INVALID_DATA_TYPE))
        .await;
    assert_eq!(settled(&mut h, 9).await, WriteStatus::FAILED);
    assert_eq!(
        reliability(&mut h, 9).await,
        Reliability::CONFIGURATION_ERROR
    );

    // Nothing was kept, so the next distribution reads again. No answer
    // comes: the read is retried like a write, then the value goes as
    // written.
    write_channel(&mut h, 9, &PropertyValue::Real(1.0), Some(8))
        .await
        .unwrap();
    let [(first, _)]: [_; 1] = next_reads(&h, 1).await.try_into().unwrap();
    tokio::time::sleep(Duration::from_millis(11_900)).await;
    let retries = sent_reads(&h);
    assert_eq!(retries.len(), 3);
    assert!(retries.iter().all(|(id, _)| *id == first));
    assert!(sent_writes(&h).is_empty());
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (invoke_id, written) = next_request(&h, bo1()).await;
    assert_eq!(written, real_octets(1.0));
    h.respond(ack(invoke_id)).await;
    assert_eq!(settled(&mut h, 9).await, WriteStatus::SUCCESSFUL);

    // A NULL value tells no datatype either, and isn't kept.
    let (written, _) = distribute(&mut h, 1.0, Some(&PropertyValue::Null), ack).await;
    assert_eq!(written, real_octets(1.0));
    write_channel(&mut h, 9, &PropertyValue::Real(1.0), Some(8))
        .await
        .unwrap();
    let [(invoke_id, request)]: [_; 1] = next_reads(&h, 1).await.try_into().unwrap();
    h.respond(read_ack(invoke_id, &request, &PropertyValue::Enumerated(1)))
        .await;
    let (invoke_id, written) = next_request(&h, bo1()).await;
    assert_eq!(written, ACTIVE);
    h.respond(ack(invoke_id)).await;
    assert_eq!(settled(&mut h, 9).await, WriteStatus::SUCCESSFUL);
}
