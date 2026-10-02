//! The `[0] Error` member that opens the Clause 21 error productions carrying
//! a first-failed coordinate (WritePropertyMultiple-Error, ChangeList-Error):
//! an opening and closing tag 0 around the application-tagged class and code.

use bacnet_encoding::{primitives, tags};
use bacnet_types::enums::{ErrorClass, ErrorCode};
use bacnet_types::error::Error;
use bytes::BytesMut;

/// Encode `[0]` around the error class and code.
pub(crate) fn encode_error_type(buf: &mut BytesMut, class: ErrorClass, code: ErrorCode) {
    tags::encode_opening_tag(buf, 0);
    primitives::encode_app_enumerated(buf, class.to_raw() as u32);
    primitives::encode_app_enumerated(buf, code.to_raw() as u32);
    tags::encode_closing_tag(buf, 0);
}

/// Decode the `[0]` error type at the start of `data`, returning the class and
/// code with the offset just past its closing tag. `what` names the
/// production in errors.
pub(crate) fn decode_error_type(
    data: &[u8],
    what: &str,
) -> Result<((ErrorClass, ErrorCode), usize), Error> {
    let (body, end) = decode_constructed(data, 0, 0, what)?;
    let (class, offset) = decode_enumerated(body, 0, what, "error-class")?;
    let (code, body_end) = decode_enumerated(body, offset, what, "error-code")?;
    if body_end != body.len() {
        return Err(Error::decoding(
            body_end,
            format!("{what} [0] has extra fields"),
        ));
    }
    Ok((
        (ErrorClass::from_raw(class), ErrorCode::from_raw(code)),
        end,
    ))
}

/// The content of the constructed `[tag_number]` at `offset`, with the offset
/// just past its closing tag.
pub(crate) fn decode_constructed<'a>(
    data: &'a [u8],
    offset: usize,
    tag_number: u8,
    what: &str,
) -> Result<(&'a [u8], usize), Error> {
    let (tag, content_start) = tags::decode_tag(data, offset)?;
    if !tag.is_opening_tag(tag_number) {
        return Err(Error::decoding(
            offset,
            format!("{what} [{tag_number}]: expected opening tag {tag_number}"),
        ));
    }
    tags::extract_context_value(data, content_start, tag_number)
}

fn decode_enumerated(
    data: &[u8],
    offset: usize,
    what: &str,
    field: &str,
) -> Result<(u16, usize), Error> {
    let (tag, content_start) = tags::decode_tag(data, offset)?;
    if tag.class != tags::TagClass::Application || tag.number != tags::app_tag::ENUMERATED {
        return Err(Error::decoding(
            offset,
            format!("{what} {field}: expected application Enumerated"),
        ));
    }
    let end = content_start
        .checked_add(tag.length as usize)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| {
            Error::decoding(content_start, format!("{what} {field}: truncated payload"))
        })?;
    let value = primitives::decode_unsigned(&data[content_start..end])?;
    let value = u16::try_from(value).map_err(|_| {
        Error::decoding(content_start, format!("{what} {field}: value exceeds u16"))
    })?;
    Ok((value, end))
}
