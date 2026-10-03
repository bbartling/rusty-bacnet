//! Clause 21 codec for `BACnetLightingCommand`: a Lighting Output's
//! Lighting_Command (Clause 12.54), and the one constructed alternative of a
//! BACnetChannelValue, where it sits inside an opening and closing tag 0 (see
//! `channel_value.rs`).
//!
//! The SEQUENCE has no frame of its own. The operation comes first under
//! primitive context tag 0, then any of five optional fields in ascending tag
//! order: REALs under tags 1 to 3 (target level, ramp rate, step increment)
//! and Unsigneds under tags 4 and 5 (fade time, priority).

use bacnet_types::constructed::BACnetLightingCommand;
use bacnet_types::enums::LightingOperation;
use bacnet_types::error::Error;
use bytes::BytesMut;

use super::members::{narrow, unsigned_member};
use super::tagged::{decode_ctx_primitive, decode_ctx_real, decode_optional_ctx};
use crate::primitives;

/// The production name the decode errors carry.
const WHAT: &str = "lighting command";

/// Encode one unframed `BACnetLightingCommand` SEQUENCE: the operation, then
/// each field that is present.
pub fn encode_lighting_command(buf: &mut BytesMut, value: &BACnetLightingCommand) {
    primitives::encode_ctx_enumerated(buf, 0, value.operation.to_raw());
    let levels = [value.target_level, value.ramp_rate, value.step_increment];
    for (tag, level) in (1..).zip(levels) {
        if let Some(level) = level {
            primitives::encode_ctx_real(buf, tag, level);
        }
    }
    if let Some(fade_time) = value.fade_time {
        primitives::encode_ctx_unsigned(buf, 4, fade_time.into());
    }
    if let Some(priority) = value.priority {
        primitives::encode_ctx_unsigned(buf, 5, priority.into());
    }
}

/// Read the Unsigned or ENUMERATED under primitive context tag `tag` at
/// `offset` and narrow it to `T`. A value too wide for `T` is recorded as
/// `oversized` and read as zero, so the rest of the structure still gets
/// checked.
fn unsigned_field<T: TryFrom<u64> + Default>(
    data: &[u8],
    offset: usize,
    tag: u8,
    too_wide: &'static str,
    oversized: &mut Option<&'static str>,
) -> Result<(T, usize), Error> {
    let (content, end) = decode_ctx_primitive(data, offset, tag, WHAT)?;
    let value = unsigned_member(content, end - content.len())?;
    Ok((narrow(value, too_wide, oversized), end))
}

/// Decode one unframed `BACnetLightingCommand` SEQUENCE at `offset`.
///
/// Returns the command and the offset just past its last field. Decoding
/// stops at the first tag that isn't the next optional field, so a caller
/// that expects exactly one command must check that the returned offset
/// reaches the end of its data, or the closing tag of its frame.
///
/// Field values aren't range-checked here; the receiver does that. Failures
/// come in three kinds:
///
/// - contents that run past the end of `data`: [`Error::BufferTooShort`];
/// - any other malformed field (a missing operation, a REAL not four octets
///   long, an Unsigned with no contents octets): [`Error::Decoding`];
/// - a well-formed command whose operation or fade time needs more than 32
///   bits, or whose priority more than 8: [`Error::OutOfRange`], naming the
///   first such field. A malformed field anywhere takes precedence.
///
/// Leading zero octets in an Unsigned or ENUMERATED are accepted;
/// [`encode_lighting_command`] always writes the shortest form.
pub fn decode_lighting_command(
    data: &[u8],
    offset: usize,
) -> Result<(BACnetLightingCommand, usize), Error> {
    let mut oversized = None;
    let (operation, offset) = unsigned_field::<u32>(
        data,
        offset,
        0,
        "operation [0] exceeds 32 bits",
        &mut oversized,
    )?;
    let (target_level, offset) = decode_optional_ctx(data, offset, 1, WHAT, decode_ctx_real)?;
    let (ramp_rate, offset) = decode_optional_ctx(data, offset, 2, WHAT, decode_ctx_real)?;
    let (step_increment, offset) = decode_optional_ctx(data, offset, 3, WHAT, decode_ctx_real)?;
    let (fade_time, offset) = decode_optional_ctx(data, offset, 4, WHAT, |data, at, tag, _| {
        unsigned_field::<u32>(
            data,
            at,
            tag,
            "fade-time [4] exceeds 32 bits",
            &mut oversized,
        )
    })?;
    let (priority, offset) = decode_optional_ctx(data, offset, 5, WHAT, |data, at, tag, _| {
        unsigned_field::<u8>(
            data,
            at,
            tag,
            "priority [5] exceeds an Unsigned8",
            &mut oversized,
        )
    })?;
    if let Some(field) = oversized {
        return Err(Error::OutOfRange(format!("{WHAT} {field}")));
    }
    Ok((
        BACnetLightingCommand {
            operation: LightingOperation::from_raw(operation),
            target_level,
            ramp_rate,
            step_increment,
            fade_time,
            priority,
        },
        offset,
    ))
}
