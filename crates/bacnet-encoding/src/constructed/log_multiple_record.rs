//! Trend Log Multiple log records (Clause 12.30.19), framed as Clause 21
//! gives BACnetLogMultipleRecord.
//!
//! A record is two constructed fields. Context tag 0 wraps the timestamp, an
//! application Date then an application Time. Context tag 1 wraps the log
//! data, one of three alternatives: a primitive context 0 holding the
//! three-bit log status, a constructed context 1 holding one entry per
//! logged member, or a primitive context 2 holding the clock change as a
//! REAL. Inside the member list each entry has its own context tag, 0 to 8
//! in [`LogValue`] declaration order: the seven plain datatypes as
//! primitives, then failure as a constructed pair of application
//! Enumerated class and code, then any-value as a constructed wrapper
//! around application-tagged contents.

use crate::{primitives, tags};
use bacnet_types::constructed::{BACnetLogMultipleRecord, LogData, LogValue};
use bacnet_types::error::Error;
use bacnet_types::primitives::{Date, Time};
use bytes::BytesMut;

const BOOLEAN: u8 = 0;
const REAL: u8 = 1;
const ENUMERATED: u8 = 2;
const UNSIGNED: u8 = 3;
const INTEGER: u8 = 4;
const BIT_STRING: u8 = 5;
const NULL: u8 = 6;
const FAILURE: u8 = 7;
const ANY: u8 = 8;

/// Encode one Trend Log Multiple record.
///
/// Fails, leaving `buf` unchanged, for a log status wider than three bits, a
/// bit string whose unused-bit count is above 7 (or nonzero with no data),
/// or an any-value whose bytes aren't complete application-tagged values.
pub fn encode_log_multiple_record(
    record: &BACnetLogMultipleRecord,
    buf: &mut BytesMut,
) -> Result<(), Error> {
    let mut out = BytesMut::new();
    tags::encode_opening_tag(&mut out, 0);
    primitives::encode_app_date(&mut out, &record.date);
    primitives::encode_app_time(&mut out, &record.time);
    tags::encode_closing_tag(&mut out, 0);

    tags::encode_opening_tag(&mut out, 1);
    match &record.log_data {
        LogData::LogStatus(status) => {
            if status & !0b111 != 0 {
                return Err(Error::OutOfRange(format!(
                    "BACnetLogMultipleRecord log-status {status:#010b} exceeds three bits"
                )));
            }
            primitives::encode_ctx_bit_string(&mut out, 0, 5, &[*status << 5]);
        }
        LogData::Values(values) => {
            tags::encode_opening_tag(&mut out, 1);
            for value in values {
                encode_value(value, &mut out)?;
            }
            tags::encode_closing_tag(&mut out, 1);
        }
        LogData::TimeChange(seconds) => primitives::encode_ctx_real(&mut out, 2, *seconds),
    }
    tags::encode_closing_tag(&mut out, 1);
    buf.extend_from_slice(&out);
    Ok(())
}

fn encode_value(value: &LogValue, buf: &mut BytesMut) -> Result<(), Error> {
    match value {
        LogValue::BooleanValue(value) => primitives::encode_ctx_boolean(buf, BOOLEAN, *value),
        LogValue::RealValue(value) => primitives::encode_ctx_real(buf, REAL, *value),
        LogValue::EnumValue(value) => primitives::encode_ctx_enumerated(buf, ENUMERATED, *value),
        LogValue::UnsignedValue(value) => primitives::encode_ctx_unsigned(buf, UNSIGNED, *value),
        LogValue::SignedValue(value) => primitives::encode_ctx_signed(buf, INTEGER, *value),
        LogValue::BitstringValue { unused_bits, data } => {
            if *unused_bits > 7 || (data.is_empty() && *unused_bits != 0) {
                return Err(Error::OutOfRange(format!(
                    "bitstring-value has {unused_bits} unused bits over {} octets",
                    data.len()
                )));
            }
            primitives::encode_ctx_bit_string(buf, BIT_STRING, *unused_bits, data);
        }
        LogValue::NullValue => tags::encode_tag(buf, NULL, tags::TagClass::Context, 0),
        LogValue::Failure {
            error_class,
            error_code,
        } => {
            tags::encode_opening_tag(buf, FAILURE);
            primitives::encode_app_enumerated(buf, *error_class);
            primitives::encode_app_enumerated(buf, *error_code);
            tags::encode_closing_tag(buf, FAILURE);
        }
        LogValue::AnyValue(bytes) => {
            check_application_values(bytes)?;
            tags::encode_opening_tag(buf, ANY);
            buf.extend_from_slice(bytes);
            tags::encode_closing_tag(buf, ANY);
        }
    }
    Ok(())
}

/// Whether `bytes` is a run of complete application-tagged values, so that
/// wrapping it cannot unbalance the surrounding tags.
fn check_application_values(bytes: &[u8]) -> Result<(), Error> {
    let mut offset = 0;
    while offset < bytes.len() {
        let (tag, start) = tags::decode_tag(bytes, offset)?;
        if tag.class != tags::TagClass::Application {
            return Err(Error::Encoding(
                "any-value holds a context tag where application data belongs".into(),
            ));
        }
        offset = if tag.number == tags::app_tag::BOOLEAN {
            start
        } else {
            start
                .checked_add(tag.length as usize)
                .filter(|end| *end <= bytes.len())
                .ok_or_else(|| Error::Encoding("any-value holds a truncated value".into()))?
        };
    }
    Ok(())
}

/// Decode one Trend Log Multiple record starting at `offset`, returning it
/// and the offset just past it.
pub fn decode_log_multiple_record(
    data: &[u8],
    offset: usize,
) -> Result<(BACnetLogMultipleRecord, usize), Error> {
    let (timestamp, data_start) = constructed(data, offset, 0, "timestamp")?;
    let (date, time) = decode_timestamp(timestamp, offset)?;
    let (body, end) = constructed(data, data_start, 1, "log-data")?;
    let log_data = decode_log_data(body, data_start)?;
    Ok((
        BACnetLogMultipleRecord {
            date,
            time,
            log_data,
        },
        end,
    ))
}

fn decode_timestamp(data: &[u8], offset: usize) -> Result<(Date, Time), Error> {
    let (date, next) = application(data, 0, tags::app_tag::DATE, 4, offset)?;
    let (time, end) = application(data, next, tags::app_tag::TIME, 4, offset)?;
    if end != data.len() {
        return Err(Error::decoding(offset, "timestamp has trailing fields"));
    }
    Ok((Date::decode(date)?, Time::decode(time)?))
}

fn decode_log_data(data: &[u8], offset: usize) -> Result<LogData, Error> {
    let (tag, start) = tags::decode_tag(data, 0)?;
    let (log_data, end) = if tag.is_context(0) {
        let (contents, end) = primitive(data, tag, start)?;
        if contents.len() != 2 || contents[0] != 5 || contents[1] & 0x1f != 0 {
            return Err(Error::decoding(
                offset,
                "log-status must be a three-bit BitString",
            ));
        }
        (LogData::LogStatus(contents[1] >> 5), end)
    } else if tag.is_opening_tag(1) {
        let (list, end) = tags::extract_context_value(data, start, 1)?;
        (LogData::Values(decode_values(list, offset)?), end)
    } else if tag.is_context(2) {
        let (contents, end) = primitive(data, tag, start)?;
        (LogData::TimeChange(primitives::decode_real(contents)?), end)
    } else {
        return Err(Error::decoding(
            offset,
            "log-data expected context [0], constructed [1], or context [2]",
        ));
    };
    if end != data.len() {
        return Err(Error::decoding(offset, "log-data has trailing fields"));
    }
    Ok(log_data)
}

fn decode_values(data: &[u8], offset: usize) -> Result<Vec<LogValue>, Error> {
    let mut values = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let (tag, start) = tags::decode_tag(data, pos)?;
        let (value, end) = if tag.is_opening_tag(FAILURE) {
            let (error, end) = tags::extract_context_value(data, start, FAILURE)?;
            let (class, next) = application(error, 0, tags::app_tag::ENUMERATED, 0, offset)?;
            let (code, last) = application(error, next, tags::app_tag::ENUMERATED, 0, offset)?;
            if last != error.len() {
                return Err(Error::decoding(offset, "failure has trailing fields"));
            }
            let value = LogValue::Failure {
                error_class: primitives::decode_unsigned_u32(class)?,
                error_code: primitives::decode_unsigned_u32(code)?,
            };
            (value, end)
        } else if tag.is_opening_tag(ANY) {
            let (contents, end) = tags::extract_context_value(data, start, ANY)?;
            (LogValue::AnyValue(contents.to_vec()), end)
        } else if tag.class == tags::TagClass::Context && !tag.is_opening && !tag.is_closing {
            let (contents, end) = primitive(data, tag, start)?;
            (decode_primitive(tag.number, contents, offset)?, end)
        } else {
            return Err(Error::decoding(offset, "log-data entry has an unknown tag"));
        };
        values.push(value);
        pos = end;
    }
    Ok(values)
}

fn decode_primitive(number: u8, contents: &[u8], offset: usize) -> Result<LogValue, Error> {
    Ok(match number {
        BOOLEAN => match contents {
            [0] => LogValue::BooleanValue(false),
            [1] => LogValue::BooleanValue(true),
            _ => return Err(Error::decoding(offset, "boolean-value must be one octet")),
        },
        REAL => LogValue::RealValue(primitives::decode_real(contents)?),
        ENUMERATED => LogValue::EnumValue(primitives::decode_unsigned_u32(contents)?),
        UNSIGNED => LogValue::UnsignedValue(primitives::decode_unsigned(contents)?),
        INTEGER => LogValue::SignedValue(primitives::decode_signed(contents)?),
        BIT_STRING => {
            let (unused_bits, data) = primitives::decode_bit_string(contents)?;
            LogValue::BitstringValue { unused_bits, data }
        }
        NULL if contents.is_empty() => LogValue::NullValue,
        _ => return Err(Error::decoding(offset, "log-data entry has an unknown tag")),
    })
}

/// The body of the constructed field `number` opening at `offset`.
fn constructed<'a>(
    data: &'a [u8],
    offset: usize,
    number: u8,
    field: &str,
) -> Result<(&'a [u8], usize), Error> {
    let (tag, start) = tags::decode_tag(data, offset)?;
    if !tag.is_opening_tag(number) {
        return Err(Error::decoding(
            offset,
            format!("BACnetLogMultipleRecord {field} expected opening tag [{number}]"),
        ));
    }
    tags::extract_context_value(data, start, number)
}

/// The contents of the primitive whose tag `tag` ends at `start`.
fn primitive(data: &[u8], tag: tags::Tag, start: usize) -> Result<(&[u8], usize), Error> {
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
fn application(
    data: &[u8],
    pos: usize,
    number: u8,
    length: u32,
    offset: usize,
) -> Result<(&[u8], usize), Error> {
    let (tag, start) = tags::decode_tag(data, pos)?;
    if tag.class != tags::TagClass::Application
        || tag.number != number
        || (length != 0 && tag.length != length)
    {
        return Err(Error::decoding(
            offset,
            format!("BACnetLogMultipleRecord expected application tag {number}"),
        ));
    }
    primitive(data, tag, start)
}
