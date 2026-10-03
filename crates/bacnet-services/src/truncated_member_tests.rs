//! Service parameters whose contents stop before their header says (#1304).
//!
//! The decoders read their tagged members with
//! `bacnet_encoding::constructed::tagged`, so a member cut short is
//! [`Error::BufferTooShort`], as it is in the constructed codecs, and a
//! fixed-size member of the wrong length stays [`Error::Decoding`] even when
//! the data also stops early.

use bacnet_types::enums::RejectReason;
use bacnet_types::error::Error;

use crate::alarm_event::{
    AcknowledgeAlarmRequest, GetEventInformationAck, GetEventInformationRequest,
};
use crate::audit::{AuditLogQueryAck, AuditLogQueryRequest};
use crate::cov::{COVNotificationRequest, SubscribeCOVPropertyRequest, SubscribeCOVRequest};
use crate::cov_multiple::{COVNotificationMultipleRequest, SubscribeCOVPropertyMultipleRequest};
use crate::life_safety::LifeSafetyOperationRequest;
use crate::list_manipulation::ChangeListError;
use crate::object_mgmt::CreateObjectError;
use crate::private_transfer::PrivateTransferError;
use crate::read_property::{ReadPropertyACK, ReadPropertyRequest};
use crate::read_range::{ReadRangeAck, ReadRangeRequest};
use crate::virtual_terminal::{VTCloseRequest, VTDataRequest, VTOpenAck, VTOpenRequest};
use crate::who_am_i::{WhoAmIRequest, YouAreRequest};
use crate::write_group::WriteGroupRequest;
use crate::write_property::WritePropertyRequest;

/// A decoder's result with the decoded value dropped.
type Decode = fn(&[u8]) -> Result<(), Error>;

macro_rules! decoder {
    ($ty:ty) => {
        (
            stringify!($ty),
            (|d: &[u8]| <$ty>::decode(d).map(drop)) as Decode,
        )
    };
}

/// `[0]` Unsigned with two contents octets announced and one present.
const PROCESS_CUT: [u8; 2] = [0x0A, 0x01];
/// `[0]` object identifier with two of its four contents octets.
const OBJECT_CUT: [u8; 3] = [0x0C, 0x00, 0x80];
/// AV-1 as `[0]`, then a `[1]` property identifier with one of two octets.
const PROPERTY_CUT: [u8; 7] = [0x0C, 0x00, 0x80, 0x00, 0x01, 0x1A, 0x55];
/// `[0]` around PROPERTY / OTHER, then a `[1]` Unsigned with one of two
/// octets.
const ERROR_THEN_CUT: [u8; 8] = [0x0E, 0x91, 0x02, 0x91, 0x00, 0x0F, 0x1A, 0x01];
/// An application Unsigned with one of two octets.
const APP_UNSIGNED_CUT: [u8; 2] = [0x22, 0x01];

#[test]
fn members_cut_short_are_a_short_buffer() {
    let cases: [((&str, Decode), &[u8]); 26] = [
        (decoder!(SubscribeCOVRequest), &PROCESS_CUT),
        (decoder!(SubscribeCOVPropertyRequest), &PROCESS_CUT),
        (decoder!(SubscribeCOVPropertyMultipleRequest), &PROCESS_CUT),
        (decoder!(COVNotificationRequest), &PROCESS_CUT),
        (decoder!(COVNotificationMultipleRequest), &PROCESS_CUT),
        (decoder!(AcknowledgeAlarmRequest), &PROCESS_CUT),
        (decoder!(LifeSafetyOperationRequest), &PROCESS_CUT),
        (decoder!(WriteGroupRequest), &PROCESS_CUT),
        (decoder!(GetEventInformationRequest), &OBJECT_CUT),
        // Opening `[0]` of the summaries, then a summary's object cut short.
        (decoder!(GetEventInformationAck), &[0x0E, 0x0C, 0x00]),
        (decoder!(AuditLogQueryRequest), &OBJECT_CUT),
        (decoder!(AuditLogQueryAck), &OBJECT_CUT),
        (decoder!(ReadRangeRequest), &OBJECT_CUT),
        (decoder!(ReadRangeAck), &OBJECT_CUT),
        (decoder!(ReadPropertyRequest), &PROPERTY_CUT),
        (decoder!(ReadPropertyACK), &PROPERTY_CUT),
        (decoder!(WritePropertyRequest), &PROPERTY_CUT),
        (decoder!(CreateObjectError), &ERROR_THEN_CUT),
        (decoder!(ChangeListError), &ERROR_THEN_CUT),
        (decoder!(PrivateTransferError), &ERROR_THEN_CUT),
        // An application ENUMERATED with one of two octets.
        (decoder!(VTOpenRequest), &[0x92, 0x00]),
        (decoder!(VTOpenAck), &APP_UNSIGNED_CUT),
        (decoder!(VTCloseRequest), &APP_UNSIGNED_CUT),
        (decoder!(VTDataRequest), &APP_UNSIGNED_CUT),
        (decoder!(WhoAmIRequest), &APP_UNSIGNED_CUT),
        (decoder!(YouAreRequest), &APP_UNSIGNED_CUT),
    ];
    for ((name, decode), data) in cases {
        let result = decode(data);
        assert!(
            matches!(result, Err(Error::BufferTooShort { .. })),
            "{name} {data:02X?}: {result:?}"
        );
    }
}

#[test]
fn fixed_size_members_of_the_wrong_length_stay_malformed_when_cut_short() {
    // Process 1, then a `[1]` object identifier whose header says three
    // octets (so the wrong length) with one present.
    let object = [0x09, 0x01, 0x1B, 0x00];
    // Process 1, AV-1, then a `[2]` BOOLEAN whose header says two octets
    // with one present.
    let boolean = [0x09, 0x01, 0x1C, 0x00, 0x80, 0x00, 0x01, 0x2A, 0x01];
    for data in [&object[..], &boolean] {
        let result = SubscribeCOVRequest::decode(data);
        assert!(
            matches!(result, Err(Error::Decoding { .. })),
            "{data:02X?}: {result:?}"
        );
    }
    // The same object identifier with a four-octet header is only cut short.
    let result = SubscribeCOVRequest::decode(&[0x09, 0x01, 0x1C, 0x00]);
    assert!(
        matches!(result, Err(Error::BufferTooShort { .. })),
        "{result:?}"
    );
}

#[test]
fn confirmed_cov_notification_rejects_keep_their_reasons() {
    let reason = |data: &[u8]| {
        let error = COVNotificationRequest::decode_detailed(data).unwrap_err();
        let reason = error.reject_reason();
        (reason, error.into_error())
    };
    // Contents cut short: a short buffer, rejected as an invalid encoding.
    let (cut, error) = reason(&PROCESS_CUT);
    assert_eq!(cut, RejectReason::INVALID_DATA_ENCODING);
    assert!(matches!(error, Error::BufferTooShort { .. }), "{error:?}");
    // A wrong tag, or a tag header cut short, is an invalid tag.
    for data in [&[0x19, 0x01][..], &[0x0D]] {
        let (wrong, error) = reason(data);
        assert_eq!(wrong, RejectReason::INVALID_TAG, "{data:02X?}");
        assert!(matches!(error, Error::Decoding { .. }), "{error:?}");
    }
    // Nothing at all is a missing parameter.
    assert_eq!(reason(&[]).0, RejectReason::MISSING_REQUIRED_PARAMETER);
    // A process identifier padded with a leading zero is an invalid
    // encoding, and one past u32 is out of range.
    let padded = [0x0A, 0x00, 0x01];
    assert_eq!(reason(&padded).0, RejectReason::INVALID_DATA_ENCODING);
    let wide = [0x0D, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(reason(&wide).0, RejectReason::PARAMETER_OUT_OF_RANGE);
}
