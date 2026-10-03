//! BACnetChannelValue (Clause 21): the value a Channel object's Present_Value
//! holds and a WriteGroup change-list entry carries.
//!
//! The production is an untagged CHOICE. Every alternative but one is a
//! primitive with its own application tag; the exception is a
//! BACnetLightingCommand, framed in a constructed context tag `[0]`. The codec
//! only finds where one value ends, checking a lighting command's structure on
//! the way, so callers can keep the octets as they arrived.

use bacnet_types::error::Error;

use super::tagged::contents;
use crate::primitives;
use crate::tags::{self, TagClass};

/// Number of the last optional field of a BACnetLightingCommand (Clause 21);
/// the operation field is number 0.
const LIGHTING_LAST_FIELD: u8 = 5;

/// Check the content octet count of lighting-command field `number`: the
/// operation, fade-time and priority fields are ENUMERATED or Unsigned and take
/// 1-4 octets here, the three level fields are REAL and take exactly 4. The
/// priority field must hold 1 to 16.
fn check_lighting_field(number: u8, content: &[u8], offset: usize) -> Result<(), Error> {
    let real = matches!(number, 1..=3);
    let length_ok = if real {
        content.len() == 4
    } else {
        (1..=4).contains(&content.len())
    };
    if !length_ok {
        return Err(Error::decoding(
            offset,
            format!(
                "lighting command field {number} has {} content octets",
                content.len()
            ),
        ));
    }
    if number == 5 {
        let priority = primitives::decode_unsigned(content)?;
        if !(1..=16).contains(&priority) {
            return Err(Error::decoding(
                offset,
                format!("lighting command priority {priority} out of range 1-16"),
            ));
        }
    }
    Ok(())
}

/// Validate the body of a constructed lighting command that starts at
/// `offset`, just after its opening tag 0; returns the offset past the closing
/// tag 0.
///
/// The operation field (context 0) must come first; fields 1-5 may follow in
/// increasing order, each at most once. Every element is a primitive context
/// tag, so no nested constructions are accepted.
fn lighting_command_end(data: &[u8], mut offset: usize) -> Result<usize, Error> {
    let mut next_number = 0u8;
    loop {
        let (tag, pos) = tags::decode_tag(data, offset)?;
        if tag.is_closing_tag(0) {
            if next_number == 0 {
                return Err(Error::decoding(
                    offset,
                    "lighting command must start with its operation field",
                ));
            }
            return Ok(pos);
        }
        if tag.class != TagClass::Context || tag.is_opening || tag.is_closing {
            return Err(Error::decoding(
                offset,
                "lighting command fields must be primitive context tags",
            ));
        }
        if next_number == 0 && tag.number != 0 {
            return Err(Error::decoding(
                offset,
                "lighting command must start with its operation field",
            ));
        }
        if tag.number < next_number {
            return Err(Error::decoding(
                offset,
                format!("lighting command field {} is out of order", tag.number),
            ));
        }
        if tag.number > LIGHTING_LAST_FIELD {
            return Err(Error::decoding(
                offset,
                format!("lighting command field {} is not defined", tag.number),
            ));
        }
        let (content, end) = contents(data, pos, tag.length)?;
        check_lighting_field(tag.number, content, offset)?;
        next_number = tag.number + 1;
        offset = end;
    }
}

/// Return the offset just past the single BACnetChannelValue starting at
/// `offset`.
///
/// The value is one well-formed application-tagged primitive of any character
/// set, or a constructed context-\[0\] BACnetLightingCommand. The lighting
/// command is checked for structure (field order, tag class, content lengths)
/// and for its priority range, but not for the REAL level ranges or the
/// operation value. Contents that run past the end of `data` fail with
/// [`Error::BufferTooShort`]; any other malformed value with
/// [`Error::Decoding`].
pub fn channel_value_end(data: &[u8], offset: usize) -> Result<usize, Error> {
    if offset >= data.len() {
        return Err(Error::decoding(offset, "missing channel value"));
    }
    let (tag, pos) = tags::decode_tag(data, offset)?;
    if tag.class == TagClass::Application {
        return primitives::validate_application_value(data, offset);
    }
    if !tag.is_opening_tag(0) {
        return Err(Error::decoding(
            offset,
            "a channel value is an application-tagged primitive or a context 0 lighting command",
        ));
    }
    lighting_command_end(data, pos)
}

/// Whether `data` is exactly one context-\[0\] lighting command, the only
/// constructed BACnetChannelValue.
pub fn is_lighting_command_channel_value(data: &[u8]) -> bool {
    data.first() == Some(&0x0E) && channel_value_end(data, 0).is_ok_and(|end| end == data.len())
}
