//! BACnetChannelValue (Clause 21): the value a Channel object's Present_Value
//! holds and a WriteGroup change-list entry carries.
//!
//! The production is an untagged CHOICE. Every alternative but one is a
//! primitive with its own application tag; the exception is a
//! BACnetLightingCommand, framed in a constructed context tag `[0]`, which is
//! read with the lighting command codec. The codec here only finds where one
//! value ends, so callers can keep the octets as they arrived.

use bacnet_types::error::Error;

use super::lighting_command::decode_fields;
use super::tagged::expect_closing;
use crate::primitives;
use crate::tags::{self, TagClass};

/// Return the offset just past the single BACnetChannelValue starting at
/// `offset`.
///
/// The value is one well-formed application-tagged primitive of any character
/// set, or a constructed context-\[0\] BACnetLightingCommand. The lighting
/// command must decode (see [`decode_lighting_command`]) and close right after
/// its last field. Then no field may be too wide for its type, and its
/// priority, when present, must be 1 to 16; its levels, fade time and
/// operation aren't range-checked. Contents that run past the end of `data`
/// fail with [`Error::BufferTooShort`]; any other malformed value with
/// [`Error::Decoding`], including a level field of the wrong length that the
/// data also cuts short, and a field too wide for its type.
///
/// [`decode_lighting_command`]: super::decode_lighting_command
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
    let (command, end, oversized) = decode_fields(data, pos)?;
    let after = expect_closing(data, end, 0, "lighting command")?;
    if let Some(field) = oversized {
        return Err(Error::decoding(offset, format!("lighting command {field}")));
    }
    if let Some(priority) = command.priority.filter(|p| !(1..=16).contains(p)) {
        return Err(Error::out_of_range(
            offset,
            format!("lighting command priority {priority} out of range 1-16"),
        ));
    }
    Ok(after)
}

/// Whether `data` is exactly one context-\[0\] lighting command, the only
/// constructed BACnetChannelValue.
pub fn is_lighting_command_channel_value(data: &[u8]) -> bool {
    data.first() == Some(&0x0E) && channel_value_end(data, 0).is_ok_and(|end| end == data.len())
}
