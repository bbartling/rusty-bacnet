//! BACnetAuditNotification object identifiers (#1303): the source and target
//! objects read like every other context-tagged object identifier, so a
//! wrong length is malformed even when the data also stops early, and four
//! octets cut short are a short buffer.

use crate::constructed::decode_audit_notification_at;
use bacnet_types::error::Error;

/// `[2]` source-device around a Device recipient, then `field`, which is
/// where the source-object `[3]` goes.
fn with_source_object(field: &[u8]) -> Vec<u8> {
    let mut data = vec![0x2E, 0x0C, 0x02, 0x00, 0x00, 0x01, 0x2F];
    data.extend_from_slice(field);
    data
}

#[test]
fn an_object_identifier_of_the_wrong_length_is_malformed_even_when_cut_short() {
    // [3] says three octets and holds one.
    let data = with_source_object(&[0x3B, 0x02]);
    match decode_audit_notification_at(&data, 0) {
        Err(Error::Decoding { offset, message }) => {
            assert_eq!(offset, 7);
            assert_eq!(
                message,
                "AuditNotification source-object: [3] object identifier has 3 contents \
                 octets, expected 4"
            );
        }
        other => panic!("expected a decoding error, got {other:?}"),
    }
}

#[test]
fn an_object_identifier_cut_short_is_a_short_buffer() {
    // [3] says four octets and holds two.
    let data = with_source_object(&[0x3C, 0x02, 0x00]);
    assert!(
        matches!(
            decode_audit_notification_at(&data, 0),
            Err(Error::BufferTooShort { need: 12, have: 10 })
        ),
        "{:?}",
        decode_audit_notification_at(&data, 0)
    );
}
