//! Field readers shared by the notification decoders.

use super::*;

/// Read the contents of the primitive context tag `expected_tag` at `offset`,
/// returning them with the offset just past the field. `field` names the
/// field in errors.
pub(super) fn decode_context<'a>(
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

/// Read a context-tagged Unsigned that fits in 32 bits.
pub(super) fn decode_context_u32(
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
pub(super) fn decode_context_enum<T>(
    data: &[u8],
    offset: usize,
    expected_tag: u8,
    field: &str,
    from_raw: fn(u32) -> T,
) -> Result<(T, usize), Error> {
    let (value, end) = decode_context_u32(data, offset, expected_tag, field)?;
    Ok((from_raw(value), end))
}

/// Read a context-tagged BOOLEAN, one content octet holding 0 or 1.
pub(super) fn decode_context_bool(
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

pub(super) fn finish_variant(
    value: NotificationParameters,
    consumed: usize,
    body_end: usize,
    variant_tag: u8,
) -> Result<NotificationParameters, Error> {
    if consumed != body_end {
        return Err(Error::decoding(
            consumed,
            format!("NotificationParameters variant {variant_tag} has unexpected fields"),
        ));
    }
    Ok(value)
}

pub(super) fn closing_tag_start(
    data: &[u8],
    end: usize,
    tag_number: u8,
    field: &str,
) -> Result<usize, Error> {
    let width = if tag_number > 14 { 2 } else { 1 };
    let start = end
        .checked_sub(width)
        .ok_or_else(|| Error::decoding(end, format!("{field} missing closing tag")))?;
    let (tag, next) = tags::decode_tag(data, start)?;
    if !tag.is_closing_tag(tag_number) || next != end {
        return Err(Error::decoding(
            start,
            format!("{field} expected closing tag {tag_number}"),
        ));
    }
    Ok(start)
}

pub(super) fn decode_context_value<T>(
    data: &[u8],
    offset: usize,
    expected_tag: u8,
    field: &str,
    decode: impl FnOnce(&[u8]) -> Result<T, Error>,
) -> Result<(T, usize), Error> {
    let (content, end) = decode_context(data, offset, expected_tag, field)?;
    Ok((decode(content)?, end))
}

pub(super) fn decode_context_u16(
    data: &[u8],
    offset: usize,
    expected_tag: u8,
    field: &str,
) -> Result<(u16, usize), Error> {
    let (content, end) = decode_context(data, offset, expected_tag, field)?;
    let value = primitives::decode_unsigned(content)?;
    let value = u16::try_from(value)
        .map_err(|_| Error::decoding(offset, format!("{field} exceeds u16")))?;
    Ok((value, end))
}

pub(super) fn decode_context_status_flags(
    data: &[u8],
    offset: usize,
    expected_tag: u8,
    field: &str,
) -> Result<(StatusFlags, usize), Error> {
    let (content, end) = decode_context(data, offset, expected_tag, field)?;
    let [4, bits] = content else {
        return Err(Error::decoding(
            offset,
            format!("{field} must contain four bits"),
        ));
    };
    if bits & 0x0f != 0 {
        return Err(Error::decoding(
            offset,
            format!("{field} must have zero padding"),
        ));
    }
    Ok((StatusFlags::from_bits_retain(bits >> 4), end))
}
