use super::*;
use bacnet_types::{
    constructed::BACnetRecipient,
    enums::{AuditOperation, ObjectType},
};

fn notification(target: Option<Vec<u8>>, current: Option<Vec<u8>>) -> BACnetAuditNotification {
    BACnetAuditNotification {
        source_timestamp: None,
        target_timestamp: None,
        source_device: BACnetRecipient::Device(
            ObjectIdentifier::new(ObjectType::DEVICE, 1).unwrap(),
        ),
        source_object: None,
        operation: AuditOperation::READ,
        source_comment: None,
        target_comment: None,
        invoke_id: None,
        source_user_id: None,
        source_user_role: None,
        target_device: BACnetRecipient::Device(
            ObjectIdentifier::new(ObjectType::DEVICE, 2).unwrap(),
        ),
        target_object: None,
        target_property: None,
        target_priority: None,
        target_value: target,
        current_value: current,
        result: None,
    }
}

fn golden(target: Option<Vec<u8>>, current: Option<Vec<u8>>, expected: &[u8]) {
    let request = AuditNotificationRequest {
        notifications: vec![notification(target, current)],
    };
    // Independent complete Clause21 vectors: [15] uses extended tag-number octets.
    assert_eq!(AuditNotificationRequest::decode(expected).unwrap(), request);
    let mut encoded = BytesMut::new();
    request.try_encode(&mut encoded).unwrap();
    assert_eq!(encoded.as_ref(), expected);
}

#[test]
fn audit_empty_values_absent_golden() {
    golden(
        None,
        None,
        &[
            0x0e, 0x2e, 0x0c, 0x02, 0, 0, 1, 0x2f, 0x49, 0, 0xae, 0x0c, 0x02, 0, 0, 2, 0xaf, 0x0f,
        ],
    );
}
#[test]
fn audit_empty_values_target_golden() {
    golden(
        Some(vec![]),
        None,
        &[
            0x0e, 0x2e, 0x0c, 0x02, 0, 0, 1, 0x2f, 0x49, 0, 0xae, 0x0c, 0x02, 0, 0, 2, 0xaf, 0xee,
            0xef, 0x0f,
        ],
    );
}
#[test]
fn audit_empty_values_current_golden() {
    golden(
        None,
        Some(vec![]),
        &[
            0x0e, 0x2e, 0x0c, 0x02, 0, 0, 1, 0x2f, 0x49, 0, 0xae, 0x0c, 0x02, 0, 0, 2, 0xaf, 0xfe,
            0x0f, 0xff, 0x0f, 0x0f,
        ],
    );
}
#[test]
fn audit_empty_values_both_golden() {
    golden(
        Some(vec![]),
        Some(vec![]),
        &[
            0x0e, 0x2e, 0x0c, 0x02, 0, 0, 1, 0x2f, 0x49, 0, 0xae, 0x0c, 0x02, 0, 0, 2, 0xaf, 0xee,
            0xef, 0xfe, 0x0f, 0xff, 0x0f, 0x0f,
        ],
    );
}
#[test]
fn audit_empty_values_codec_has_no_reporter_32_octet_limit() {
    // 33 complete application NULL values are valid TLV, even though Reporter omits them.
    let request = AuditNotificationRequest {
        notifications: vec![notification(Some(vec![0; 33]), Some(vec![0; 34]))],
    };
    let mut encoded = BytesMut::new();
    request.try_encode(&mut encoded).unwrap();
    assert_eq!(AuditNotificationRequest::decode(&encoded).unwrap(), request);
}
