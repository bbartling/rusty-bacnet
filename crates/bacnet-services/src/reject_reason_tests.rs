//! The Reject reason each syntax fault in a confirmed request draws (#1446):
//! the decoder reports the fault's kind, and [`Error::reject_reason`] names
//! the reason the server answers with.

use bacnet_types::enums::RejectReason;
use bacnet_types::error::Error;

use crate::cov::SubscribeCOVPropertyRequest;
use crate::file::AtomicWriteFileRequest;
use crate::object_mgmt::CreateObjectRequest;
use crate::read_property::ReadPropertyRequest;

/// AV-1 as a `[0]` object identifier.
const AV_1: [u8; 5] = [0x0C, 0x00, 0x80, 0x00, 0x01];

/// The reason the error `decode` returns for `data` draws.
fn reason<T: std::fmt::Debug>(decode: fn(&[u8]) -> Result<T, Error>, data: &[u8]) -> RejectReason {
    let error = decode(data).unwrap_err();
    error
        .reject_reason()
        .unwrap_or_else(|| panic!("{data:02X?}: {error:?} names no reason"))
}

#[test]
fn read_property_faults_name_their_reasons() {
    use RejectReason as R;
    let decode = ReadPropertyRequest::decode;
    let cat = |tail: &[u8]| [&AV_1[..], tail].concat();
    let cases: [(&str, Vec<u8>, RejectReason); 9] = [
        (
            "an argument after the last",
            cat(&[0x19, 0x55, 0x21, 0x01]),
            R::TOO_MANY_ARGUMENTS,
        ),
        (
            "a closing tag after the last",
            cat(&[0x19, 0x55, 0x0F]),
            R::INVALID_TAG,
        ),
        (
            "no property identifier",
            AV_1.to_vec(),
            R::MISSING_REQUIRED_PARAMETER,
        ),
        (
            "the property identifier cut short",
            cat(&[0x1A, 0x55]),
            R::MISSING_REQUIRED_PARAMETER,
        ),
        (
            "a tag header cut short",
            cat(&[0x1D]),
            R::MISSING_REQUIRED_PARAMETER,
        ),
        (
            "the index where the property is due",
            cat(&[0x29, 0x02]),
            R::MISSING_REQUIRED_PARAMETER,
        ),
        (
            "an application object identifier",
            vec![0xC4, 0x00, 0x80, 0x00, 0x01],
            R::INVALID_TAG,
        ),
        ("a reserved tag form", cat(&[0x1E, 0x1F]), R::INVALID_TAG),
        (
            "an object identifier of three octets",
            vec![0x0B, 0x00, 0x80, 0x00, 0x19, 0x55],
            R::OTHER,
        ),
    ];
    for (what, data, expected) in cases {
        assert_eq!(reason(decode, &data), expected, "{what}");
    }
}

#[test]
fn frames_and_choices_name_their_reasons() {
    use RejectReason as R;
    // SubscribeCOVProperty: process 1 and AV-1, then the [4] reference that
    // never closes, or holds a member past the reference.
    let head = [
        &[0x09, 0x01, 0x1C, 0x00, 0x80, 0x00, 0x01][..],
        &[0x4E, 0x09, 0x55],
    ]
    .concat();
    let decode = SubscribeCOVPropertyRequest::decode;
    assert_eq!(reason(decode, &head), R::MISSING_REQUIRED_PARAMETER);
    let crowded = [&head[..], &[0x29, 0x01, 0x39, 0x01, 0x4F]].concat();
    assert_eq!(reason(decode, &crowded), R::TOO_MANY_ARGUMENTS);
    // CreateObject: an object specifier frame closing empty, or holding a
    // tag neither alternative has.
    let decode = CreateObjectRequest::decode;
    assert_eq!(reason(decode, &[0x0E, 0x0F]), R::MISSING_REQUIRED_PARAMETER);
    assert_eq!(reason(decode, &[0x0E, 0x29, 0x01, 0x0F]), R::INVALID_TAG);
}

#[test]
fn atomic_write_file_record_counts_name_their_reasons() {
    use RejectReason as R;
    let decode = AtomicWriteFileRequest::decode;
    // File 1, then a record write starting at 0 that counts `count` records
    // and holds `records`.
    let write = |count: u8, records: &[u8]| {
        [
            &[0xC4, 0x02, 0x80, 0x00, 0x01, 0x1E, 0x31, 0x00, 0x21, count][..],
            records,
            &[0x1F],
        ]
        .concat()
    };
    assert_eq!(
        reason(decode, &write(2, &[0x61, 0xAA])),
        R::MISSING_REQUIRED_PARAMETER
    );
    assert_eq!(
        reason(decode, &write(1, &[0x61, 0xAA, 0x61, 0xBB])),
        R::TOO_MANY_ARGUMENTS
    );
}
