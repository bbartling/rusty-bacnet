//! Structural recognition of the Clause 21 error productions that replace the
//! plain class/code pair. Each opens with the error class and code inside
//! `[0]`, then adds its own members:
//!
//! - WritePropertyMultiple-Error (service 16): a `[1]` frame around the
//!   BACnetObjectPropertyReference of the first failed write attempt;
//! - ChangeList-Error (AddListElement 8, RemoveListElement 9) and
//!   CreateObject-Error (10): a `[1]` Unsigned first failed element number;
//! - ConfirmedPrivateTransfer-Error (18): `[1]` vendor identifier, `[2]`
//!   service number and an optional `[3]` frame of error parameters;
//! - VTClose-Error (22): an optional `[1]` frame of application Unsigned8
//!   session identifiers.
//!
//! SubscribeCOVPropertyMultiple-Error (30) is a CHOICE instead: the `[0]`
//! error alone, or a `[1]` frame holding the failed subscription's `[0]`
//! object identifier, `[1]` property reference and `[2]` error.

use bacnet_types::enums::{ConfirmedServiceChoice, ErrorClass, ErrorCode};
use bacnet_types::error::Error;

use crate::constructed::decode_object_property_reference;
use crate::{primitives, tags};

/// Decodes the members after `[0]` from an offset, returning the offset past
/// them.
type Members = fn(&[u8], usize, &str) -> Result<usize, Error>;

/// The class and code of `data` when it is the complete formal error body of
/// `service`; `None` when the service has no formal body or `data` does not
/// open with an opening tag the production starts with. A body that opens
/// with one but is malformed is an error.
pub(super) fn decode_formal_body(
    service: ConfirmedServiceChoice,
    data: &[u8],
) -> Result<Option<(ErrorClass, ErrorCode)>, Error> {
    let (what, members): (&str, Members) = match service {
        s if s == ConfirmedServiceChoice::WRITE_PROPERTY_MULTIPLE => {
            ("formal WPM Error", first_failed_write_attempt)
        }
        s if s == ConfirmedServiceChoice::ADD_LIST_ELEMENT
            || s == ConfirmedServiceChoice::REMOVE_LIST_ELEMENT =>
        {
            ("ChangeList-Error", first_failed_element_number)
        }
        s if s == ConfirmedServiceChoice::CREATE_OBJECT => {
            ("CreateObject-Error", first_failed_element_number)
        }
        s if s == ConfirmedServiceChoice::CONFIRMED_PRIVATE_TRANSFER => {
            ("ConfirmedPrivateTransfer-Error", private_transfer_members)
        }
        s if s == ConfirmedServiceChoice::VT_CLOSE => ("VTClose-Error", vt_session_identifiers),
        s if s == ConfirmedServiceChoice::SUBSCRIBE_COV_PROPERTY_MULTIPLE => {
            return subscribe_cov_property_multiple(data);
        }
        _ => return Ok(None),
    };
    if !opens_with(data, 0) {
        return Ok(None);
    }
    let (pair, offset) = error_type(data, 0, 0, what)?;
    finish(data, members(data, offset, what)?, what)?;
    Ok(Some(pair))
}

/// Whether `data` starts with opening tag `number`.
fn opens_with(data: &[u8], number: u8) -> bool {
    tags::decode_tag(data, 0).is_ok_and(|(tag, _)| tag.is_opening_tag(number))
}

/// The CHOICE: `[0]` Error alone, or `[1]` first-failed-subscription, whose
/// `[2]` Error supplies the class and code.
fn subscribe_cov_property_multiple(data: &[u8]) -> Result<Option<(ErrorClass, ErrorCode)>, Error> {
    const WHAT: &str = "SubscribeCOVPropertyMultiple-Error";
    if opens_with(data, 0) {
        let (pair, end) = error_type(data, 0, 0, WHAT)?;
        finish(data, end, WHAT)?;
        return Ok(Some(pair));
    }
    if !opens_with(data, 1) {
        return Ok(None);
    }
    let (_, content_start) = tags::decode_tag(data, 0)?;
    let (subscription, end) = tags::extract_context_value(data, content_start, 1)?;
    finish(data, end, WHAT)?;

    let (content, offset) = primitive(subscription, 0, 0, WHAT)?;
    if content.len() != 4 {
        return Err(Error::decoding(
            0,
            format!("{WHAT} monitored object identifier is not four octets"),
        ));
    }
    // BACnetPropertyReference: [0] property identifier, optional [1] index.
    let (reference, offset) = constructed(subscription, offset, 1, WHAT)?;
    let (property, mut reference_end) = primitive(reference, 0, 0, WHAT)?;
    primitives::decode_unsigned_u32(property)?;
    if reference_end != reference.len() {
        let (index, index_end) = primitive(reference, reference_end, 1, WHAT)?;
        primitives::decode_unsigned_u32(index)?;
        reference_end = index_end;
    }
    finish(reference, reference_end, WHAT)?;
    let (pair, end) = error_type(subscription, offset, 2, WHAT)?;
    finish(subscription, end, WHAT)?;
    Ok(Some(pair))
}

/// WPM's `[1]` frame around the first failed write attempt.
fn first_failed_write_attempt(data: &[u8], offset: usize, what: &str) -> Result<usize, Error> {
    let (reference, end) = constructed(data, offset, 1, what)?;
    decode_object_property_reference(reference)?;
    Ok(end)
}

/// ChangeList's and CreateObject's `[1]` Unsigned first failed element number.
fn first_failed_element_number(data: &[u8], offset: usize, what: &str) -> Result<usize, Error> {
    let (number, end) = primitive(data, offset, 1, what)?;
    primitives::decode_unsigned_u32(number)?;
    Ok(end)
}

/// ConfirmedPrivateTransfer's `[1]` vendor identifier and `[2]` service
/// number, then its optional `[3]` error parameters.
fn private_transfer_members(data: &[u8], offset: usize, what: &str) -> Result<usize, Error> {
    let (vendor_id, offset) = primitive(data, offset, 1, what)?;
    primitives::decode_unsigned_u32(vendor_id)?;
    let (service_number, offset) = primitive(data, offset, 2, what)?;
    primitives::decode_unsigned_u32(service_number)?;
    if offset == data.len() {
        return Ok(offset);
    }
    let (_, end) = constructed(data, offset, 3, what)?;
    Ok(end)
}

/// VTClose's optional `[1]` frame of application Unsigned8 identifiers.
fn vt_session_identifiers(data: &[u8], offset: usize, what: &str) -> Result<usize, Error> {
    if offset == data.len() {
        return Ok(offset);
    }
    let (sessions, end) = constructed(data, offset, 1, what)?;
    let mut position = 0;
    while position < sessions.len() {
        let (tag, content_start) = tags::decode_tag(sessions, position)?;
        if tag.class != tags::TagClass::Application || tag.number != tags::app_tag::UNSIGNED {
            return Err(Error::decoding(
                position,
                format!("{what} session identifier expected application Unsigned"),
            ));
        }
        let content_end = payload_end(sessions, content_start, tag.length, what)?;
        primitives::decode_unsigned_u8(&sessions[content_start..content_end])?;
        position = content_end;
    }
    Ok(end)
}

fn finish(data: &[u8], end: usize, what: &str) -> Result<(), Error> {
    if end != data.len() {
        return Err(Error::decoding(end, format!("{what} has trailing content")));
    }
    Ok(())
}

/// The content of the context-tagged primitive `[number]` at `offset`, with
/// the offset past it.
fn primitive<'a>(
    data: &'a [u8],
    offset: usize,
    number: u8,
    what: &str,
) -> Result<(&'a [u8], usize), Error> {
    let (tag, content_start) = tags::decode_tag(data, offset)?;
    if !tag.is_context(number) {
        return Err(Error::decoding(
            offset,
            format!("{what} expected context tag {number}"),
        ));
    }
    let end = payload_end(data, content_start, tag.length, what)?;
    Ok((&data[content_start..end], end))
}

/// The content of the constructed `[number]` at `offset`, with the offset
/// past its closing tag.
fn constructed<'a>(
    data: &'a [u8],
    offset: usize,
    number: u8,
    what: &str,
) -> Result<(&'a [u8], usize), Error> {
    let (tag, content_start) = tags::decode_tag(data, offset)?;
    if !tag.is_opening_tag(number) {
        return Err(Error::decoding(
            offset,
            format!("{what} expected opening tag {number}"),
        ));
    }
    tags::extract_context_value(data, content_start, number)
}

/// The class and code inside the constructed `[number]` at `offset`, with the
/// offset past its closing tag.
fn error_type(
    data: &[u8],
    offset: usize,
    number: u8,
    what: &str,
) -> Result<((ErrorClass, ErrorCode), usize), Error> {
    let (error_body, end) = constructed(data, offset, number, what)?;
    let (class, offset) = decode_enumerated(error_body, 0, "error-class", what)?;
    let (code, body_end) = decode_enumerated(error_body, offset, "error-code", what)?;
    if body_end != error_body.len() {
        return Err(Error::decoding(
            body_end,
            format!("{what} [{number}] has extra fields"),
        ));
    }
    Ok((
        (ErrorClass::from_raw(class), ErrorCode::from_raw(code)),
        end,
    ))
}

fn payload_end(data: &[u8], content_start: usize, length: u32, what: &str) -> Result<usize, Error> {
    content_start
        .checked_add(length as usize)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| Error::decoding(content_start, format!("{what} payload is truncated")))
}

fn decode_enumerated(
    data: &[u8],
    offset: usize,
    field: &str,
    what: &str,
) -> Result<(u16, usize), Error> {
    let (tag, content_start) = tags::decode_tag(data, offset)?;
    if tag.class != tags::TagClass::Application || tag.number != tags::app_tag::ENUMERATED {
        return Err(Error::decoding(
            offset,
            format!("{what} {field} expected application Enumerated"),
        ));
    }
    let end = payload_end(data, content_start, tag.length, what)?;
    let value = primitives::decode_unsigned(&data[content_start..end])?;
    let value = u16::try_from(value)
        .map_err(|_| Error::decoding(content_start, format!("{field} exceeds u16")))?;
    Ok((value, end))
}
