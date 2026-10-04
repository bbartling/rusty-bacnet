//! Who-Is, I-Am, Who-Has, I-Have and You-Are. I-Am, I-Have and You-Are are
//! all application-tagged (Clause 21), so any other tag is refused; Who-Is
//! and Who-Has read context tags. All five refuse octets after their last
//! member (#1411); a receiver drops such a request, as it can't answer one.

use super::*;
use crate::who_am_i::YouAreRequest;
use crate::who_has::{IHaveRequest, WhoHasRequest};
use crate::who_is::{IAmRequest, WhoIsRequest};

/// Device 1234 as an application object identifier.
const DEVICE_1234: &[u8] = &[0xC4, 0x02, 0x00, 0x04, 0xD2];
/// AI-1 as an application object identifier.
const AI_1: &[u8] = &[0xC4, 0x00, 0x00, 0x00, 0x01];
/// "T" as an application CharacterString.
const NAME_T: &[u8] = &[0x72, 0x00, 0x54];
/// Low limit 1 in `[0]` and high limit 10 in `[1]`.
const LIMITS: &[u8] = &[0x09, 0x01, 0x19, 0x0A];

#[test]
fn who_is_request() {
    let rows: &[Row<'_>] = &[
        ("no limits", &[], Decodes),
        ("both limits", LIMITS, Decodes),
        ("low limit cut short", &[0x0A, 0x01], Short),
        ("high limit cut short", &[0x09, 0x01, 0x1A, 0x0A], Short),
        ("low limit above high", &[0x09, 0x0A, 0x19, 0x01], Malformed),
        // One limit alone reads as no limits.
        ("only the low limit", &[0x09, 0x01], Decodes),
        ("only the high limit", &[0x19, 0x0A], Decodes),
        // Anything the limits leave unread refuses the request.
        ("a context [2] alone", &[0x29, 0x00], Malformed),
        (
            "limits as application Unsigneds",
            &[0x21, 0x01, 0x21, 0x0A],
            Malformed,
        ),
        (
            "limits in the wrong order",
            &[0x19, 0x0A, 0x09, 0x01],
            Malformed,
        ),
        (
            "an octet after the low limit alone",
            &[0x09, 0x01, 0x00],
            Malformed,
        ),
        (
            "an octet after the limits",
            &cat(&[LIMITS, &[0x00]]),
            Malformed,
        ),
    ];
    check(decoder!(WhoIsRequest), rows);
}

#[test]
fn i_am_request() {
    // Max APDU 1476, no segmentation, vendor 42.
    let rest: &[u8] = &[0x22, 0x05, 0xC4, 0x91, 0x00, 0x21, 0x2A];
    let rows: &[Row<'_>] = &[
        ("well formed", &cat(&[DEVICE_1234, rest]), Decodes),
        (
            "identifier as context [0]",
            &cat(&[&[0x0C, 0x02, 0x00, 0x04, 0xD2], rest]),
            Malformed,
        ),
        ("identifier cut short", &[0xC4, 0x02, 0x00], Short),
        (
            "identifier of five octets, cut short",
            &[0xC5, 0x05, 0x02, 0x00],
            Malformed,
        ),
        (
            "max APDU cut short",
            &cat(&[DEVICE_1234, &[0x22, 0x05]]),
            Short,
        ),
        (
            "segmentation as an Unsigned",
            &cat(&[DEVICE_1234, &[0x22, 0x05, 0xC4, 0x21, 0x00, 0x21, 0x2A]]),
            Malformed,
        ),
        (
            "vendor cut short",
            &cat(&[DEVICE_1234, &[0x22, 0x05, 0xC4, 0x91, 0x00, 0x22, 0x2A]]),
            Short,
        ),
        (
            "an octet after the vendor",
            &cat(&[DEVICE_1234, rest, &[0x00]]),
            Malformed,
        ),
    ];
    check(decoder!(IAmRequest), rows);
}

#[test]
fn who_has_request() {
    let av_1: &[u8] = &[0x2C, 0x00, 0x80, 0x00, 0x01];
    let rows: &[Row<'_>] = &[
        ("by identifier", &cat(&[LIMITS, av_1]), Decodes),
        ("by name", &[0x3A, 0x00, 0x54], Decodes),
        ("low limit cut short", &[0x0A, 0x01], Short),
        ("identifier cut short", &[0x2C, 0x00, 0x80], Short),
        (
            "identifier of three octets",
            &[0x2B, 0x00, 0x80, 0x00],
            Malformed,
        ),
        ("name cut short", &[0x3B, 0x00, 0x54], Short),
        (
            "identifier as an application tag",
            &[0xC4, 0x00, 0x80, 0x00, 0x01],
            Malformed,
        ),
        ("object as [4]", &[0x49, 0x01], Malformed),
        (
            "an octet after the identifier",
            &cat(&[av_1, &[0x00]]),
            Malformed,
        ),
        (
            "an octet after the name",
            &[0x3A, 0x00, 0x54, 0x00],
            Malformed,
        ),
        (
            "both the identifier and the name",
            &cat(&[av_1, &[0x3A, 0x00, 0x54]]),
            Malformed,
        ),
    ];
    check(decoder!(WhoHasRequest), rows);
}

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
            Malformed,
        ),
    ];
    check(decoder!(IHaveRequest), rows);
}

#[test]
fn you_are_request() {
    // Vendor 260, model "M", serial "S".
    let identity: &[u8] = &[0x22, 0x01, 0x04, 0x72, 0x00, 0x4D, 0x72, 0x00, 0x53];
    let device_1: &[u8] = &[0xC4, 0x02, 0x00, 0x00, 0x01];
    let rows: &[Row<'_>] = &[
        (
            "identifier and MAC",
            &cat(&[identity, device_1, &[0x61, 0x0A]]),
            Decodes,
        ),
        (
            "vendor as context [0]",
            &cat(&[&[0x0A, 0x01, 0x04], &identity[3..], device_1]),
            Malformed,
        ),
        (
            "model cut short",
            &[0x22, 0x01, 0x04, 0x73, 0x00, 0x4D],
            Short,
        ),
        (
            "identifier cut short",
            &cat(&[identity, &[0xC4, 0x02, 0x00]]),
            Short,
        ),
        (
            "identifier of five octets, cut short",
            &cat(&[identity, &[0xC5, 0x05, 0x02, 0x00]]),
            Malformed,
        ),
        (
            "identifier as context [0]",
            &cat(&[identity, &[0x0C, 0x02, 0x00, 0x00, 0x01]]),
            Malformed,
        ),
        (
            "an octet after the identifier",
            &cat(&[identity, device_1, &[0x00]]),
            Malformed,
        ),
    ];
    check(decoder!(YouAreRequest), rows);
}
