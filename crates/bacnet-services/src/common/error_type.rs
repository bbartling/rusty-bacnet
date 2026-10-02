//! The Error member of the Clause 21 error productions that replace the plain
//! class/code pair (WritePropertyMultiple-Error, ChangeList-Error,
//! CreateObject-Error, SubscribeCOVPropertyMultiple-Error,
//! ConfirmedPrivateTransfer-Error, VTClose-Error): an opening and closing
//! context tag around the application-tagged class and code, `[0]` in every
//! production except inside SubscribeCOVPropertyMultiple's failed subscription.

use crate::common::decode_context_u32;
use bacnet_encoding::apdu::ErrorPdu;
use bacnet_encoding::{primitives, tags};
use bacnet_types::enums::{ConfirmedServiceChoice, ErrorClass, ErrorCode};
use bacnet_types::error::Error;
use bytes::BytesMut;

/// Encode `[0]` around the error class and code.
pub(crate) fn encode_error_type(buf: &mut BytesMut, class: ErrorClass, code: ErrorCode) {
    encode_error_in(buf, 0, class, code);
}

/// Encode `[tag_number]` around the error class and code.
pub(crate) fn encode_error_in(
    buf: &mut BytesMut,
    tag_number: u8,
    class: ErrorClass,
    code: ErrorCode,
) {
    tags::encode_opening_tag(buf, tag_number);
    primitives::encode_app_enumerated(buf, class.to_raw() as u32);
    primitives::encode_app_enumerated(buf, code.to_raw() as u32);
    tags::encode_closing_tag(buf, tag_number);
}

/// Decode the `[0]` error type at the start of `data`, returning the class and
/// code with the offset just past its closing tag. `what` names the
/// production in errors.
pub(crate) fn decode_error_type(
    data: &[u8],
    what: &str,
) -> Result<((ErrorClass, ErrorCode), usize), Error> {
    decode_error_in(data, 0, 0, what)
}

/// Decode the constructed `[tag_number]` error at `offset`, returning the
/// class and code with the offset just past its closing tag.
pub(crate) fn decode_error_in(
    data: &[u8],
    offset: usize,
    tag_number: u8,
    what: &str,
) -> Result<((ErrorClass, ErrorCode), usize), Error> {
    let (body, end) = decode_constructed(data, offset, tag_number, what)?;
    let (class, offset) = decode_enumerated(body, 0, what, "error-class")?;
    let (code, body_end) = decode_enumerated(body, offset, what, "error-code")?;
    if body_end != body.len() {
        return Err(Error::decoding(
            body_end,
            format!("{what} [{tag_number}] has extra fields"),
        ));
    }
    Ok((
        (ErrorClass::from_raw(class), ErrorCode::from_raw(code)),
        end,
    ))
}

/// Encode `[0]` Error then `[1]` Unsigned first-failed-element-number, the
/// shape ChangeList-Error and CreateObject-Error share.
pub(crate) fn encode_element_error(
    buf: &mut BytesMut,
    class: ErrorClass,
    code: ErrorCode,
    first_failed_element_number: u32,
) {
    encode_error_type(buf, class, code);
    primitives::encode_ctx_unsigned(buf, 1, u64::from(first_failed_element_number));
}

/// Decode one complete `[0]` Error, `[1]` Unsigned body with no trailing
/// content.
pub(crate) fn decode_element_error(
    data: &[u8],
    what: &str,
) -> Result<(ErrorClass, ErrorCode, u32), Error> {
    let ((class, code), offset) = decode_error_type(data, what)?;
    let (number, end) = decode_context_u32(
        data,
        offset,
        1,
        &format!("{what} first-failed-element-number"),
    )?;
    finish(data, end, what)?;
    Ok((class, code, number))
}

/// Refuse content after the end of a production.
pub(crate) fn finish(data: &[u8], end: usize, what: &str) -> Result<(), Error> {
    if end != data.len() {
        return Err(Error::decoding(end, format!("{what} has trailing content")));
    }
    Ok(())
}

/// The Error PDU answering `service_choice` with `encode`'s body. The APDU
/// encoder sends it in place of the plain pair only when it is the formal
/// body of that service; otherwise it follows a plain class and code.
pub(crate) fn error_pdu(
    invoke_id: u8,
    service_choice: ConfirmedServiceChoice,
    (error_class, error_code): (ErrorClass, ErrorCode),
    encode: impl FnOnce(&mut BytesMut),
) -> ErrorPdu {
    let mut body = BytesMut::new();
    encode(&mut body);
    ErrorPdu {
        invoke_id,
        service_choice,
        error_class,
        error_code,
        error_data: body.freeze(),
    }
}

/// Decode `pdu`'s body with `decode` when it answers one of `services`, and
/// refuse a body whose class and code disagree with the PDU's. A plain
/// class/code error, which older devices send, fails to decode.
pub(crate) fn decode_error_pdu<T>(
    pdu: &ErrorPdu,
    services: &[ConfirmedServiceChoice],
    what: &str,
    decode: impl FnOnce(&[u8]) -> Result<T, Error>,
    pair: impl FnOnce(&T) -> (ErrorClass, ErrorCode),
) -> Result<T, Error> {
    if !services.contains(&pdu.service_choice) {
        return Err(Error::decoding(
            0,
            format!("ErrorPdu for {:?} is not a {what}", pdu.service_choice),
        ));
    }
    let decoded = decode(&pdu.error_data)?;
    if pair(&decoded) != (pdu.error_class, pdu.error_code) {
        return Err(Error::decoding(
            0,
            format!("{what} body disagrees with ErrorPdu class/code"),
        ));
    }
    Ok(decoded)
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
