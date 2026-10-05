//! Detailed confirmed-COV decoding and Reject classification.

use bacnet_encoding::constructed::tagged::{
    decode_canonical_unsigned, decode_ctx_primitive, expect_end, misplaced_tag,
};
use bacnet_encoding::constructed::{
    decode_bacnet_property_value_in_list_detailed, PropertyValueDecodeFailure,
};
use bacnet_encoding::tags;
use bacnet_types::enums::RejectReason;
use bacnet_types::error::Error;
use bacnet_types::primitives::ObjectIdentifier;

use crate::common::MAX_DECODED_ITEMS;
use crate::cov::COVNotificationRequest;

/// Structured failure returned when decoding a confirmed COV notification.
///
/// Confirmed-service responders need the Clause 18.9 Reject reason in
/// addition to the ordinary decoder error retained by
/// [`COVNotificationRequest::decode`].
#[derive(Debug)]
pub struct COVNotificationDecodeError {
    error: Error,
    reject_reason: RejectReason,
}

impl COVNotificationDecodeError {
    fn new(error: Error, reject_reason: RejectReason) -> Self {
        Self {
            error,
            reject_reason,
        }
    }

    /// Reject reason appropriate for this confirmed-service syntax failure.
    pub fn reject_reason(&self) -> RejectReason {
        self.reject_reason
    }

    /// Recover the ordinary decoder error used by the compatibility API.
    pub fn into_error(self) -> Error {
        self.error
    }
}

type COVDecodeResult<T> = Result<T, COVNotificationDecodeError>;

fn failure(error: Error, reject_reason: RejectReason) -> COVNotificationDecodeError {
    COVNotificationDecodeError::new(error, reject_reason)
}

/// A syntax fault with the reason the server's rule gives it (#1446): the
/// data ending where a member or closing tag is due, or a member cut short,
/// is MISSING_REQUIRED_PARAMETER; a tag that doesn't fit, INVALID_TAG;
/// octets past the end, TOO_MANY_ARGUMENTS.
fn syntax(error: Error) -> COVNotificationDecodeError {
    let reject_reason = error.reject_reason().unwrap_or(RejectReason::OTHER);
    failure(error, reject_reason)
}

/// The contents of the required primitive context tag `expected_tag` at
/// `offset`, with [`syntax`]'s reasons for a missing member, one cut short
/// or a tag that doesn't fit.
fn decode_required_context<'a>(
    data: &'a [u8],
    offset: usize,
    expected_tag: u8,
    field: &str,
) -> COVDecodeResult<(&'a [u8], usize)> {
    if offset >= data.len() {
        return Err(syntax(Error::missing(
            offset,
            format!("{field} is missing"),
        )));
    }
    decode_ctx_primitive(data, offset, expected_tag, field).map_err(syntax)
}

fn decode_required_u32(
    data: &[u8],
    offset: usize,
    expected_tag: u8,
    field: &str,
) -> COVDecodeResult<(u32, usize)> {
    let (content, end) = decode_required_context(data, offset, expected_tag, field)?;
    let value = decode_canonical_unsigned(content, offset, field)
        .map_err(|error| failure(error, RejectReason::INVALID_DATA_ENCODING))?;
    let value = u32::try_from(value).map_err(|_| {
        failure(
            Error::decoding(offset, format!("{field} exceeds u32")),
            RejectReason::PARAMETER_OUT_OF_RANGE,
        )
    })?;
    Ok((value, end))
}

impl COVNotificationRequest {
    /// Decode a confirmed COV notification and retain its Clause 18.9 Reject
    /// classification if the service parameters are malformed.
    pub fn decode_detailed(data: &[u8]) -> COVDecodeResult<Self> {
        let mut offset = 0;

        let (subscriber_process_identifier, end) =
            decode_required_u32(data, offset, 0, "COVNotification process-id")?;
        offset = end;

        let (content, end) = decode_required_context(data, offset, 1, "COVNotification device-id")?;
        let initiating_device_identifier = ObjectIdentifier::decode(content)
            .map_err(|error| failure(error, RejectReason::INVALID_DATA_ENCODING))?;
        offset = end;

        let (content, end) =
            decode_required_context(data, offset, 2, "COVNotification monitored-id")?;
        let monitored_object_identifier = ObjectIdentifier::decode(content)
            .map_err(|error| failure(error, RejectReason::INVALID_DATA_ENCODING))?;
        offset = end;

        let (time_remaining, end) =
            decode_required_u32(data, offset, 3, "COVNotification time-remaining")?;
        offset = end;

        if offset >= data.len() {
            return Err(syntax(Error::missing(
                offset,
                "COVNotification list-of-values is missing",
            )));
        }
        let (tag, tag_end) = tags::decode_tag(data, offset).map_err(syntax)?;
        if !tag.is_opening_tag(4) {
            return Err(syntax(misplaced_tag(
                &tag,
                Some(4),
                offset,
                "COVNotification expected opening tag 4",
            )));
        }
        offset = tag_end;

        let mut values = Vec::new();
        loop {
            if offset >= data.len() {
                return Err(syntax(Error::missing(
                    offset,
                    "COVNotification missing closing tag 4",
                )));
            }
            let (tag, tag_end) = tags::decode_tag(data, offset).map_err(syntax)?;
            if tag.is_closing_tag(4) {
                offset = tag_end;
                break;
            }
            if values.len() >= MAX_DECODED_ITEMS {
                return Err(failure(
                    Error::decoding(offset, "COVNotification values exceeds max"),
                    RejectReason::BUFFER_OVERFLOW,
                ));
            }
            let (pv, new_offset) = decode_bacnet_property_value_in_list_detailed(data, offset, 4)
                .map_err(|failed| {
                let reject_reason = match failed.kind {
                    PropertyValueDecodeFailure::Syntax(reason) => reason,
                    PropertyValueDecodeFailure::PriorityOutOfRange => {
                        RejectReason::PARAMETER_OUT_OF_RANGE
                    }
                };
                failure(failed.error, reject_reason)
            })?;
            values.push(pv);
            offset = new_offset;
        }
        if values.is_empty() {
            return Err(failure(
                Error::decoding(
                    offset,
                    "COVNotification list-of-values must contain at least one value",
                ),
                RejectReason::PARAMETER_OUT_OF_RANGE,
            ));
        }
        expect_end(data, offset, offset, "COVNotification").map_err(syntax)?;

        Ok(Self {
            subscriber_process_identifier,
            initiating_device_identifier,
            monitored_object_identifier,
            time_remaining,
            list_of_values: values,
        })
    }
}
