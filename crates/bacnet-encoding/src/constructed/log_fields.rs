//! The fields the three log record codecs share: the constructed timestamp,
//! the three-bit log status, the error pair, bit-string checks and the
//! any-value wrapper.
//!
//! Every record of Clause 21's BACnetLogRecord, BACnetEventLogRecord and
//! BACnetLogMultipleRecord opens with context 0 around an application Date
//! then an application Time, and each record kind reuses the same encodings
//! for its log-status, failure and any-value alternatives under its own tag
//! numbers. `record` names the record kind in error messages.

use super::validate_tlv_sequence;
use crate::{primitives, tags};
use bacnet_types::error::Error;
use bacnet_types::primitives::{Date, Time};
use bytes::BytesMut;

/// Write the timestamp field: context 0 around an application Date and Time.
pub(super) fn encode_timestamp(buf: &mut BytesMut, date: &Date, time: &Time) {
    tags::encode_opening_tag(buf, 0);
    primitives::encode_app_date(buf, date);
    primitives::encode_app_time(buf, time);
    tags::encode_closing_tag(buf, 0);
}

/// Read the timestamp field opening at `offset`, returning it and the offset
/// of the field after it.
pub(super) fn decode_timestamp(
    data: &[u8],
    offset: usize,
    record: &str,
) -> Result<(Date, Time, usize), Error> {
    let (body, end) = constructed(data, offset, 0, record, "timestamp")?;
    let (date, next) = application(body, 0, tags::app_tag::DATE, 4, offset, record)?;
    let (time, last) = application(body, next, tags::app_tag::TIME, 4, offset, record)?;
    if last != body.len() {
        return Err(Error::decoding(
            offset,
            format!("{record} timestamp has trailing fields"),
        ));
    }
    Ok((Date::decode(date)?, Time::decode(time)?, end))
}

/// Write a log status as the primitive context `tag`: a BIT STRING of three
/// bits. Fails for a status wider than three bits.
pub(super) fn encode_log_status(
    buf: &mut BytesMut,
    tag: u8,
    status: u8,
    record: &str,
) -> Result<(), Error> {
    if status & !0b111 != 0 {
        return Err(Error::OutOfRange(format!(
            "{record} log-status {status:#010b} exceeds three bits"
        )));
    }
    primitives::encode_ctx_bit_string(buf, tag, 5, &[status << 5]);
    Ok(())
}

/// The log status in a primitive's `contents`: exactly a three-bit BIT
/// STRING with its padding clear.
pub(super) fn decode_log_status(contents: &[u8], offset: usize, record: &str) -> Result<u8, Error> {
    match contents {
        [5, bits] if bits & 0x1f == 0 => Ok(bits >> 5),
        _ => Err(Error::decoding(
            offset,
            format!("{record} log-status must be a three-bit BitString"),
        )),
    }
}

/// Write the error pair as constructed context `tag` around an application
/// Enumerated class then code.
pub(super) fn encode_failure(buf: &mut BytesMut, tag: u8, error_class: u32, error_code: u32) {
    tags::encode_opening_tag(buf, tag);
    primitives::encode_app_enumerated(buf, error_class);
    primitives::encode_app_enumerated(buf, error_code);
    tags::encode_closing_tag(buf, tag);
}

/// The class and code in the body of a failure alternative.
pub(super) fn decode_failure(
    body: &[u8],
    offset: usize,
    record: &str,
) -> Result<(u32, u32), Error> {
    let (class, next) = application(body, 0, tags::app_tag::ENUMERATED, 0, offset, record)?;
    let (code, last) = application(body, next, tags::app_tag::ENUMERATED, 0, offset, record)?;
    if last != body.len() {
        return Err(Error::decoding(
            offset,
            format!("{record} failure has trailing fields"),
        ));
    }
    Ok((
        primitives::decode_unsigned_u32(class)?,
        primitives::decode_unsigned_u32(code)?,
    ))
}

/// Refuse a bit string whose unused-bit count is above 7, or nonzero with no
/// data.
pub(super) fn check_bit_string(unused_bits: u8, data: &[u8]) -> Result<(), Error> {
    if unused_bits > 7 || (data.is_empty() && unused_bits != 0) {
        return Err(Error::OutOfRange(format!(
            "bitstring-value has {unused_bits} unused bits over {} octets",
            data.len()
        )));
    }
    Ok(())
}

/// Write an any-value as constructed context `tag` around `bytes`, which
/// must be complete tagged values with every context tag balanced, so that
/// wrapping them cannot unbalance the record.
pub(super) fn encode_any_value(buf: &mut BytesMut, tag: u8, bytes: &[u8]) -> Result<(), Error> {
    validate_tlv_sequence(bytes, "any-value")
        .map_err(|error| Error::Encoding(error.to_string()))?;
    tags::encode_opening_tag(buf, tag);
    buf.extend_from_slice(bytes);
    tags::encode_closing_tag(buf, tag);
    Ok(())
}

/// The contents of an any-value whose body is `body`, held to the rule its
/// encoder applies.
pub(super) fn decode_any_value(body: &[u8]) -> Result<Vec<u8>, Error> {
    validate_tlv_sequence(body, "any-value")?;
    Ok(body.to_vec())
}

/// The body of the constructed field `number` opening at `offset`, and the
/// offset just past its closing tag.
pub(super) fn constructed<'a>(
    data: &'a [u8],
    offset: usize,
    number: u8,
    record: &str,
    field: &str,
) -> Result<(&'a [u8], usize), Error> {
    let (tag, start) = tags::decode_tag(data, offset)?;
    if !tag.is_opening_tag(number) {
        return Err(Error::decoding(
            offset,
            format!("{record} {field} expected opening tag [{number}]"),
        ));
    }
    tags::extract_context_value(data, start, number)
}

/// The contents of the primitive whose tag `tag` ends at `start`.
pub(super) fn primitive(
    data: &[u8],
    tag: tags::Tag,
    start: usize,
) -> Result<(&[u8], usize), Error> {
    let end = start
        .checked_add(tag.length as usize)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| {
            Error::buffer_too_short(start.saturating_add(tag.length as usize), data.len())
        })?;
    Ok((&data[start..end], end))
}

/// The contents of the application `number` value at `pos`, with exactly
/// `length` octets unless `length` is zero.
fn application<'a>(
    data: &'a [u8],
    pos: usize,
    number: u8,
    length: u32,
    offset: usize,
    record: &str,
) -> Result<(&'a [u8], usize), Error> {
    let (tag, start) = tags::decode_tag(data, pos)?;
    if tag.class != tags::TagClass::Application
        || tag.number != number
        || (length != 0 && tag.length != length)
    {
        return Err(Error::decoding(
            offset,
            format!("{record} expected application tag {number}"),
        ));
    }
    primitive(data, tag, start)
}
