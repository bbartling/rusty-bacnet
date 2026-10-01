//! Clause 21 codec for `BACnetLandingCallStatus`, the value of the Elevator
//! Group object's Landing_Call_Control and of each Landing_Calls element
//! (Clause 12.58).
//!
//! The SEQUENCE has three primitive context-tagged members: floor-number
//! `[0]`, then the untagged command CHOICE, whose alternatives carry their
//! own tags (direction `[1]` or destination `[2]`), then an optional
//! floor-text `[3]`.
//! There is no opening/closing frame, and a BACnetLIST of these values is the
//! plain concatenation of its elements.

use bacnet_types::constructed::{BACnetLandingCallStatus, LandingCallCommand};
use bacnet_types::enums::LiftCarDirection;
use bacnet_types::error::Error;
use bytes::BytesMut;

use crate::primitives;
use crate::tags;

/// Encode one unframed `BACnetLandingCallStatus` SEQUENCE.
///
/// Fails, leaving `buf` untouched, only when `floor_text` is too long to
/// encode.
pub fn encode_landing_call_status(
    buf: &mut BytesMut,
    value: &BACnetLandingCallStatus,
) -> Result<(), Error> {
    let mut encoded = BytesMut::new();
    primitives::encode_ctx_unsigned(&mut encoded, 0, value.floor_number.into());
    match value.command {
        LandingCallCommand::Direction(direction) => {
            primitives::encode_ctx_enumerated(&mut encoded, 1, direction.to_raw())
        }
        LandingCallCommand::Destination(floor) => {
            primitives::encode_ctx_unsigned(&mut encoded, 2, floor.into())
        }
    }
    if let Some(text) = &value.floor_text {
        primitives::encode_ctx_character_string(&mut encoded, 3, text)?;
    }
    buf.extend_from_slice(&encoded);
    Ok(())
}

/// Encode a BACnetLIST of `BACnetLandingCallStatus` as concatenated elements.
///
/// Fails, leaving `buf` untouched, when any element fails to encode.
pub fn encode_landing_call_status_list(
    buf: &mut BytesMut,
    values: &[BACnetLandingCallStatus],
) -> Result<(), Error> {
    let mut encoded = BytesMut::new();
    for value in values {
        encode_landing_call_status(&mut encoded, value)?;
    }
    buf.extend_from_slice(&encoded);
    Ok(())
}

/// Decode one unframed `BACnetLandingCallStatus` SEQUENCE at `offset`.
///
/// Returns the value and the offset just past it. Decoding stops after the
/// command member, or after floor-text `[3]` when that follows, so a caller
/// that expects exactly one value must check the returned offset reaches the
/// end of its data. Floor-number and destination must fit an Unsigned8, and a
/// direction must fit 32 bits; the direction is otherwise kept as received,
/// reserved and proprietary values included, for the receiver to judge.
pub fn decode_landing_call_status(
    data: &[u8],
    offset: usize,
) -> Result<(BACnetLandingCallStatus, usize), Error> {
    let (tag, content) = tags::decode_tag(data, offset)?;
    if !tag.is_context(0) {
        return Err(Error::decoding(
            offset,
            "landing call status requires floor-number [0]",
        ));
    }
    let (floor, offset) = member_content(data, content, tag.length)?;
    let floor_number = primitives::decode_unsigned_u8(floor)
        .map_err(|_| Error::decoding(content, "floor-number [0] must be an Unsigned8"))?;

    let (tag, content) = tags::decode_tag(data, offset)?;
    let (command, mut offset) = if tag.is_context(1) {
        let (raw, end) = member_content(data, content, tag.length)?;
        let direction = primitives::decode_unsigned_u32(raw)
            .map_err(|_| Error::decoding(content, "direction [1] must fit 32 bits"))?;
        (
            LandingCallCommand::Direction(LiftCarDirection::from_raw(direction)),
            end,
        )
    } else if tag.is_context(2) {
        let (raw, end) = member_content(data, content, tag.length)?;
        let destination = primitives::decode_unsigned_u8(raw)
            .map_err(|_| Error::decoding(content, "destination [2] must be an Unsigned8"))?;
        (LandingCallCommand::Destination(destination), end)
    } else {
        return Err(Error::decoding(
            offset,
            "landing call status requires direction [1] or destination [2]",
        ));
    };

    let mut floor_text = None;
    if offset < data.len() {
        let (tag, content) = tags::decode_tag(data, offset)?;
        if tag.is_context(3) {
            let (text, end) = member_content(data, content, tag.length)?;
            floor_text = Some(primitives::decode_character_string(text)?);
            offset = end;
        }
    }

    Ok((
        BACnetLandingCallStatus {
            floor_number,
            command,
            floor_text,
        },
        offset,
    ))
}

/// Decode a complete BACnetLIST of `BACnetLandingCallStatus`.
///
/// Every byte must belong to an element; an empty input is an empty list.
pub fn decode_landing_call_status_list(data: &[u8]) -> Result<Vec<BACnetLandingCallStatus>, Error> {
    let mut values = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let (value, end) = decode_landing_call_status(data, offset)?;
        values.push(value);
        offset = end;
    }
    Ok(values)
}

/// The content octets of a primitive member and the offset just past them.
fn member_content(data: &[u8], content: usize, length: u32) -> Result<(&[u8], usize), Error> {
    let end = usize::try_from(length)
        .ok()
        .and_then(|length| content.checked_add(length))
        .ok_or_else(|| Error::decoding(content, "landing call status member length overflow"))?;
    if end > data.len() {
        return Err(Error::buffer_too_short(end, data.len()));
    }
    Ok((&data[content..end], end))
}
