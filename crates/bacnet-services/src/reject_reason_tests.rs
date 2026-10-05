//! The Reject reason each fault in a confirmed request's parameters draws
//! (#1446): the decoder reports the fault's kind, and
//! [`Error::reject_reason`] names the reason the server answers with.

use bacnet_types::enums::RejectReason;
use bacnet_types::error::Error;

use crate::audit::AuditNotificationRequest;
use crate::cov::SubscribeCOVPropertyRequest;
use crate::device_mgmt::DeviceCommunicationControlRequest;
use crate::enrollment_summary::GetEnrollmentSummaryRequest;
use crate::file::AtomicWriteFileRequest;
use crate::object_mgmt::CreateObjectRequest;
use crate::read_property::ReadPropertyRequest;
use crate::read_range::ReadRangeRequest;

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
    let cases: [(&str, Vec<u8>, RejectReason); 12] = [
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
        // A closing tag that closes no open frame is a tag that doesn't
        // fit, at the start or where the property is due.
        ("a closing tag alone", vec![0x0F], R::INVALID_TAG),
        (
            "a closing tag where the property is due",
            cat(&[0x1F]),
            R::INVALID_TAG,
        ),
        // An encoding not valid for its datatype, and a value too large for
        // its field.
        (
            "an object identifier of three octets",
            vec![0x0B, 0x00, 0x80, 0x00, 0x19, 0x55],
            R::INVALID_DATA_ENCODING,
        ),
        (
            "a property identifier past u32",
            cat(&[0x1D, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]),
            R::PARAMETER_OUT_OF_RANGE,
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
    // The [4] frame closing where its property identifier is due: missing.
    // A closing tag of another number there closes no open frame.
    let empty = [0x09, 0x01, 0x1C, 0x00, 0x80, 0x00, 0x01, 0x4E, 0x4F];
    assert_eq!(reason(decode, &empty), R::MISSING_REQUIRED_PARAMETER);
    let mismatched = [0x09, 0x01, 0x1C, 0x00, 0x80, 0x00, 0x01, 0x4E, 0x5F];
    assert_eq!(reason(decode, &mismatched), R::INVALID_TAG);
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
    // A record count past the decoder's item limit is a buffer capacity.
    let huge = [
        0xC4, 0x02, 0x80, 0x00, 0x01, 0x1E, 0x31, 0x00, 0x23, 0x01, 0x00, 0x00, 0x1F,
    ];
    assert_eq!(reason(decode, &huge), R::BUFFER_OVERFLOW);
}

#[test]
fn ranges_lists_and_character_sets_name_their_reasons() {
    use RejectReason as R;
    // GetEnrollmentSummary: acknowledgment filter ALL, then a priority
    // filter whose minimum is above its maximum.
    let inverted = [0x09, 0x00, 0x4E, 0x09, 0x05, 0x19, 0x01, 0x4F];
    assert_eq!(
        reason(GetEnrollmentSummaryRequest::decode, &inverted),
        R::PARAMETER_OUT_OF_RANGE
    );
    // ReadRange of AV-1's Log_Buffer at array index zero, and by position
    // with a count of zero.
    let decode = ReadRangeRequest::decode;
    let at = |tail: &[u8]| [&AV_1[..], &[0x19, 0x83], tail].concat();
    assert_eq!(
        reason(decode, &at(&[0x29, 0x00])),
        R::PARAMETER_OUT_OF_RANGE
    );
    assert_eq!(
        reason(decode, &at(&[0x3E, 0x21, 0x01, 0x31, 0x00, 0x3F])),
        R::PARAMETER_OUT_OF_RANGE
    );
    // A ConfirmedAuditNotification with no notifications: out of range, as
    // an empty COV list of values is.
    assert_eq!(
        reason(AuditNotificationRequest::decode, &[0x0E, 0x0F]),
        R::PARAMETER_OUT_OF_RANGE
    );
    // A DCC password in a character set the decoder doesn't convert (JIS X
    // 0208), and in one the standard doesn't define.
    let decode = DeviceCommunicationControlRequest::decode;
    assert_eq!(reason(decode, &[0x19, 0x00, 0x2A, 0x02, 0x41]), R::OTHER);
    assert_eq!(
        reason(decode, &[0x19, 0x00, 0x2A, 0x09, 0x41]),
        R::INVALID_DATA_ENCODING
    );
}
