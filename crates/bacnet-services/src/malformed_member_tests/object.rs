//! Object and property access: ReadProperty, WriteProperty, the
//! ReadPropertyMultiple ACK, CreateObject, DeleteObject and the list
//! services. DeleteObject's identifier is application-tagged (Clause 21);
//! the others read context tags.

use super::*;
use crate::object_mgmt::DeleteObjectRequest;

/// AV-1 as an application object identifier.
const AV_1_APP: &[u8] = &[0xC4, 0x00, 0x80, 0x00, 0x01];

#[test]
fn delete_object_request() {
    let rows: &[Row<'_>] = &[
        ("well formed", AV_1_APP, Decodes),
        (
            "identifier as context [0]",
            &[0x0C, 0x00, 0x80, 0x00, 0x01],
            Malformed,
        ),
        (
            "identifier as an Unsigned",
            &[0x24, 0x00, 0x80, 0x00, 0x01],
            Malformed,
        ),
        ("identifier cut short", &[0xC4, 0x00, 0x80], Short),
        (
            "identifier of three octets",
            &[0xC3, 0x00, 0x80, 0x00],
            Malformed,
        ),
        (
            "identifier of five octets, cut short",
            &[0xC5, 0x05, 0x00, 0x80],
            Malformed,
        ),
        ("empty", &[], Malformed),
        (
            "an octet after the identifier",
            &cat(&[AV_1_APP, &[0x00]]),
            Decodes,
        ),
    ];
    check(decoder!(DeleteObjectRequest), rows);
}
