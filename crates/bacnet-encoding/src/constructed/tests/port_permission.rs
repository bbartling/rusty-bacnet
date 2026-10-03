//! Port_Filter elements (#1225): golden vectors and refusal of malformed
//! elements.

use super::*;
use bacnet_types::constructed::BACnetPortPermission;

#[test]
fn port_permission_round_trips_golden_elements() {
    for (bytes, permission) in [
        (
            &[0x09, 0x00, 0x19, 0x01][..],
            BACnetPortPermission {
                port_id: 0,
                enabled: true,
            },
        ),
        (
            &[0x09, 0xFF, 0x19, 0x00][..],
            BACnetPortPermission {
                port_id: 255,
                enabled: false,
            },
        ),
    ] {
        let mut buf = BytesMut::new();
        encode_port_permission(&mut buf, &permission);
        assert_eq!(&buf[..], bytes);
        assert_eq!(
            decode_port_permission(bytes, 0).unwrap(),
            (permission, bytes.len())
        );
    }
    // Two elements back to back decode one at a time.
    let pair = [0x09, 0x01, 0x19, 0x01, 0x09, 0x02, 0x19, 0x00];
    let (first, next) = decode_port_permission(&pair, 0).unwrap();
    let (second, end) = decode_port_permission(&pair, next).unwrap();
    assert_eq!((first.port_id, first.enabled), (1, true));
    assert_eq!(
        (second.port_id, second.enabled, end),
        (2, false, pair.len())
    );
}

#[test]
fn port_permission_refuses_malformed_elements() {
    for bytes in [
        // A port ID past Unsigned8.
        &[0x0A, 0x01, 0x00, 0x19, 0x01][..],
        // The enabled flag missing, or truncated.
        &[0x09, 0x00][..],
        &[0x09, 0x00, 0x19][..],
        // A BOOLEAN other than 0 or 1.
        &[0x09, 0x00, 0x19, 0x02][..],
        // Members out of order.
        &[0x19, 0x01, 0x09, 0x00][..],
        // An application-tagged port ID.
        &[0x21, 0x00, 0x19, 0x01][..],
    ] {
        assert!(
            decode_port_permission(bytes, 0).is_err(),
            "{bytes:02X?} must not decode"
        );
    }
}
