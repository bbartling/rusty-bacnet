//! Shared BACnet service data types per ASHRAE 135-2020 Clause 21.

use bacnet_encoding::primitives;
use bacnet_encoding::tags;
use bacnet_types::error::Error;

pub use bacnet_types::constructed::BACnetPropertyValue;

/// Safety limit for decoded sequences to prevent unbounded allocations.
pub const MAX_DECODED_ITEMS: usize = 10_000;

pub(crate) mod error_type;

pub(crate) fn decode_context<'a>(
    data: &'a [u8],
    offset: usize,
    expected_tag: u8,
    field: &str,
) -> Result<(&'a [u8], usize), Error> {
    let (tag, pos) = tags::decode_tag(data, offset)?;
    if !tag.is_context(expected_tag) {
        return Err(Error::decoding(
            offset,
            format!("{field} expected context tag {expected_tag}"),
        ));
    }
    let end = pos
        .checked_add(tag.length as usize)
        .ok_or_else(|| Error::decoding(pos, format!("{field} length overflow")))?;
    if end > data.len() {
        return Err(Error::decoding(pos, format!("{field} truncated")));
    }
    Ok((&data[pos..end], end))
}

/// Read the content octets of the application-tagged primitive `expected_tag` at `offset`,
/// returning them with the offset just past the element. `field` names the element in errors.
pub(crate) fn decode_application<'a>(
    data: &'a [u8],
    offset: usize,
    expected_tag: u8,
    field: &str,
) -> Result<(&'a [u8], usize), Error> {
    let (tag, pos) = tags::decode_tag(data, offset)?;
    if tag.class != tags::TagClass::Application
        || tag.is_opening
        || tag.is_closing
        || tag.number != expected_tag
    {
        return Err(Error::decoding(
            offset,
            format!("{field} expected application tag {expected_tag}"),
        ));
    }
    let end = pos
        .checked_add(tag.length as usize)
        .ok_or_else(|| Error::decoding(pos, format!("{field} length overflow")))?;
    if end > data.len() {
        return Err(Error::decoding(pos, format!("{field} truncated")));
    }
    Ok((&data[pos..end], end))
}

pub(crate) fn decode_context_u32(
    data: &[u8],
    offset: usize,
    expected_tag: u8,
    field: &str,
) -> Result<(u32, usize), Error> {
    let (content, end) = decode_context(data, offset, expected_tag, field)?;
    let value = primitives::decode_unsigned(content)?;
    let value = u32::try_from(value)
        .map_err(|_| Error::decoding(offset, format!("{field} exceeds u32")))?;
    Ok((value, end))
}

/// Decode a context-tagged Enumerated into an open enumeration newtype through its `from_raw`
/// constructor, so values outside the named set (including proprietary ones) are kept as-is.
pub(crate) fn decode_context_enum<T>(
    data: &[u8],
    offset: usize,
    expected_tag: u8,
    field: &str,
    from_raw: fn(u32) -> T,
) -> Result<(T, usize), Error> {
    let (value, end) = decode_context_u32(data, offset, expected_tag, field)?;
    Ok((from_raw(value), end))
}

pub(crate) fn decode_context_bool(
    data: &[u8],
    offset: usize,
    expected_tag: u8,
    field: &str,
) -> Result<(bool, usize), Error> {
    let (content, end) = decode_context(data, offset, expected_tag, field)?;
    let value = match content {
        [0] => false,
        [1] => true,
        _ => {
            return Err(Error::decoding(
                offset,
                format!("{field} expected Boolean 0 or 1"),
            ));
        }
    };
    Ok((value, end))
}
