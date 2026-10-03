//! Member helpers the elevator codecs share: landing calls, landing doors,
//! assigned landing calls and car call lists.
//!
//! Each decodes primitive Unsigned members and keeps two kinds of failure
//! apart, so a property writer can answer with the matching Clause 15.9.1.3
//! error: a malformed member fails at once, while a well-formed member whose
//! value doesn't fit its type is only recorded, and the codec reports it as
//! [`Error::OutOfRange`] once the rest of the value has been checked. The
//! codecs read each member's contents with [`super::tagged`].

use bacnet_types::error::Error;

/// The value of an Unsigned member's content octets, or `None` when the
/// encoding is well formed but the value needs more than 64 bits. Empty
/// content is malformed.
pub(super) fn unsigned_member(content: &[u8], at: usize) -> Result<Option<u64>, Error> {
    if content.is_empty() {
        return Err(Error::decoding(at, "Unsigned member has no content octets"));
    }
    let first = content.iter().position(|&octet| octet != 0);
    let significant = first.map_or(&[][..], |first| &content[first..]);
    if significant.len() > 8 {
        return Ok(None);
    }
    Ok(Some(
        significant
            .iter()
            .fold(0, |value, &octet| (value << 8) | u64::from(octet)),
    ))
}

/// Narrow a decoded Unsigned to its member type. When it doesn't fit, record
/// `what` as the first oversized member (if none is recorded yet) and yield a
/// placeholder, so decoding can still check the rest of the structure.
pub(super) fn narrow<T: TryFrom<u64> + Default>(
    value: Option<u64>,
    what: &'static str,
    oversized: &mut Option<&'static str>,
) -> T {
    match value.map(T::try_from) {
        Some(Ok(value)) => value,
        _ => {
            oversized.get_or_insert(what);
            T::default()
        }
    }
}
