//! Who-Is, I-Am, Who-Has, I-Have and You-Are. I-Am, I-Have and You-Are are
//! all application-tagged (Clause 21), so any other tag is refused; Who-Is
//! and Who-Has read context tags.

use super::*;
use crate::who_has::IHaveRequest;

/// Device 1234 as an application object identifier.
const DEVICE_1234: &[u8] = &[0xC4, 0x02, 0x00, 0x04, 0xD2];
/// AI-1 as an application object identifier.
const AI_1: &[u8] = &[0xC4, 0x00, 0x00, 0x00, 0x01];
/// "T" as an application CharacterString.
const NAME_T: &[u8] = &[0x72, 0x00, 0x54];

#[test]
fn i_have_request() {
    let rows: &[Row<'_>] = &[
        ("well formed", &cat(&[DEVICE_1234, AI_1, NAME_T]), Decodes),
        (
            "device identifier as context [0]",
            &cat(&[&[0x0C, 0x02, 0x00, 0x04, 0xD2], AI_1, NAME_T]),
            Malformed,
        ),
        (
            "object identifier as context [1]",
            &cat(&[DEVICE_1234, &[0x1C, 0x00, 0x00, 0x00, 0x01], NAME_T]),
            Malformed,
        ),
        (
            "object name as context [2]",
            &cat(&[DEVICE_1234, AI_1, &[0x2A, 0x00, 0x54]]),
            Malformed,
        ),
        (
            "object name as an OCTET STRING",
            &cat(&[DEVICE_1234, AI_1, &[0x62, 0x00, 0x54]]),
            Malformed,
        ),
        ("device identifier cut short", &[0xC4, 0x02, 0x00], Short),
        (
            "device identifier of three octets",
            &cat(&[&[0xC3, 0x02, 0x00, 0x04], AI_1, NAME_T]),
            Malformed,
        ),
        (
            "object name cut short",
            &cat(&[DEVICE_1234, AI_1, &[0x73, 0x00, 0x54]]),
            Short,
        ),
        ("object name missing", &cat(&[DEVICE_1234, AI_1]), Malformed),
        (
            "an octet after the name",
            &cat(&[DEVICE_1234, AI_1, NAME_T, &[0x00]]),
            Decodes,
        ),
    ];
    check(decoder!(IHaveRequest), rows);
}
