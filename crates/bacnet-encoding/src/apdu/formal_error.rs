//! Structural recognition of the Clause 21 error productions that replace the
//! plain class/code pair: WritePropertyMultiple-Error (service 16) and
//! ChangeList-Error (AddListElement 8 and RemoveListElement 9). Both open with
//! the error class and code inside `[0]`; WPM follows it with a `[1]`
//! BACnetObjectPropertyReference frame, ChangeList with a `[1]` Unsigned.

use bacnet_types::enums::{ConfirmedServiceChoice, ErrorClass, ErrorCode};
use bacnet_types::error::Error;

use crate::constructed::decode_object_property_reference;
use crate::{primitives, tags};

/// Decodes the member after `[0]` at an offset, returning the offset past it.
type SecondMember = fn(&[u8], usize) -> Result<usize, Error>;

/// The class and code of `data` when it is the complete formal error body of
/// `service`; `None` when the service has no formal body or `data` does not
/// open with `[0]`. A body that opens with `[0]` but is malformed is an error.
pub(super) fn decode_formal_body(
    service: ConfirmedServiceChoice,
    data: &[u8],
) -> Result<Option<(ErrorClass, ErrorCode)>, Error> {
    let (what, second): (&str, SecondMember) = match service {
        s if s == ConfirmedServiceChoice::WRITE_PROPERTY_MULTIPLE => {
            ("formal WPM Error", first_failed_write_attempt)
        }
        s if s == ConfirmedServiceChoice::ADD_LIST_ELEMENT
            || s == ConfirmedServiceChoice::REMOVE_LIST_ELEMENT =>
        {
            ("ChangeList-Error", first_failed_element_number)
        }
        _ => return Ok(None),
    };
    if data.is_empty() {
        return Ok(None);
    }
    let (first, content_start) = match tags::decode_tag(data, 0) {
        Ok(decoded) => decoded,
        Err(_) => return Ok(None),
    };
    if !first.is_opening_tag(0) {
        return Ok(None);
    }

    let (error_body, offset) = tags::extract_context_value(data, content_start, 0)?;
    let pair = decode_error_pair(error_body, what)?;
    let end = second(data, offset)?;
    if end != data.len() {
        return Err(Error::decoding(end, format!("{what} has trailing content")));
    }
    Ok(Some(pair))
}

/// WPM's `[1]` frame around the first failed write attempt.
fn first_failed_write_attempt(data: &[u8], offset: usize) -> Result<usize, Error> {
    let (reference_opening, reference_start) = tags::decode_tag(data, offset)?;
    if !reference_opening.is_opening_tag(1) {
        return Err(Error::decoding(
            offset,
            "formal WPM Error expected opening tag 1",
        ));
    }
    let (reference_body, end) = tags::extract_context_value(data, reference_start, 1)?;
    decode_object_property_reference(reference_body)?;
    Ok(end)
}

/// ChangeList's `[1]` Unsigned first failed element number.
fn first_failed_element_number(data: &[u8], offset: usize) -> Result<usize, Error> {
    let (tag, content_start) = tags::decode_tag(data, offset)?;
    if !tag.is_context(1) {
        return Err(Error::decoding(
            offset,
            "ChangeList-Error expected context tag 1",
        ));
    }
    let end = content_start
        .checked_add(tag.length as usize)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| {
            Error::decoding(content_start, "first-failed-element-number is truncated")
        })?;
    primitives::decode_unsigned_u32(&data[content_start..end])?;
    Ok(end)
}

fn decode_error_pair(data: &[u8], what: &str) -> Result<(ErrorClass, ErrorCode), Error> {
    let (class, offset) = decode_enumerated(data, 0, "error-class", what)?;
    let (code, end) = decode_enumerated(data, offset, "error-code", what)?;
    if end != data.len() {
        return Err(Error::decoding(end, format!("{what} [0] has extra fields")));
    }
    Ok((ErrorClass::from_raw(class), ErrorCode::from_raw(code)))
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
    let end = content_start
        .checked_add(tag.length as usize)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| Error::decoding(content_start, format!("{field} payload is truncated")))?;
    let value = primitives::decode_unsigned(&data[content_start..end])?;
    let value = u16::try_from(value)
        .map_err(|_| Error::decoding(content_start, format!("{field} exceeds u16")))?;
    Ok((value, end))
}
