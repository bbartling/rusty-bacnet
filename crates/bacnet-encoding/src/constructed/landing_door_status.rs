//! Clause 21 codec for `BACnetLandingDoorStatus`, the value of each element of
//! the Lift object's Landing_Door_Status array (Clause 12.59).
//!
//! The SEQUENCE has one member, landing-doors `[0]`: a SEQUENCE OF framed by
//! opening and closing tag 0. Each landing door inside the frame is a pair of
//! primitive context tags, floor-number `[0]` (Unsigned8) then door-status
//! `[1]` (BACnetDoorStatus). A car door with no landing doors encodes as the
//! empty frame.

use bacnet_types::constructed::{BACnetLandingDoorStatus, LandingDoor};
use bacnet_types::enums::DoorStatus;
use bacnet_types::error::Error;
use bytes::BytesMut;

use super::MAX_FRAMED_ITEMS;
use crate::primitives;
use crate::tags;

/// Encode one `BACnetLandingDoorStatus` SEQUENCE.
pub fn encode_landing_door_status(buf: &mut BytesMut, value: &BACnetLandingDoorStatus) {
    tags::encode_opening_tag(buf, 0);
    for door in &value.landing_doors {
        primitives::encode_ctx_unsigned(buf, 0, door.floor_number.into());
        primitives::encode_ctx_enumerated(buf, 1, door.door_status.to_raw());
    }
    tags::encode_closing_tag(buf, 0);
}

/// Decode one `BACnetLandingDoorStatus` SEQUENCE at `offset`.
///
/// Returns the value and the offset just past its closing tag, so a caller
/// that expects exactly one value must check the returned offset reaches the
/// end of its data. A missing frame or member, a floor-number above 255, a
/// door-status wider than 32 bits, truncated data, or more than 10,000
/// landing doors fails. Any door-status that fits 32 bits is kept as
/// received, reserved and proprietary values included, for the receiver to
/// judge.
pub fn decode_landing_door_status(
    data: &[u8],
    offset: usize,
) -> Result<(BACnetLandingDoorStatus, usize), Error> {
    let (tag, mut offset) = tags::decode_tag(data, offset)?;
    if !tag.is_opening_tag(0) {
        return Err(Error::decoding(
            offset,
            "landing door status requires landing-doors [0]",
        ));
    }
    let mut landing_doors = Vec::new();
    loop {
        let (tag, content) = tags::decode_tag(data, offset)?;
        if tag.is_closing_tag(0) {
            return Ok((BACnetLandingDoorStatus { landing_doors }, content));
        }
        if landing_doors.len() >= MAX_FRAMED_ITEMS {
            return Err(Error::decoding(
                offset,
                "landing door status exceeds the decoded item limit",
            ));
        }
        if !tag.is_context(0) {
            return Err(Error::decoding(
                offset,
                "landing door requires floor-number [0]",
            ));
        }
        let (floor, next) = member_content(data, content, tag.length)?;
        let floor_number = primitives::decode_unsigned_u8(floor).map_err(|_| {
            Error::decoding(content, "landing door floor-number [0] is not Unsigned8")
        })?;

        let (tag, content) = tags::decode_tag(data, next)?;
        if !tag.is_context(1) {
            return Err(Error::decoding(
                next,
                "landing door requires door-status [1]",
            ));
        }
        let (status, next) = member_content(data, content, tag.length)?;
        let door_status = primitives::decode_unsigned_u32(status).map_err(|_| {
            Error::decoding(content, "landing door door-status [1] exceeds 32 bits")
        })?;

        landing_doors.push(LandingDoor {
            floor_number,
            door_status: DoorStatus::from_raw(door_status),
        });
        offset = next;
    }
}

/// The content octets of a primitive member and the offset just past them.
fn member_content(data: &[u8], content: usize, length: u32) -> Result<(&[u8], usize), Error> {
    let end = usize::try_from(length)
        .ok()
        .and_then(|length| content.checked_add(length))
        .ok_or_else(|| Error::decoding(content, "landing door member length overflow"))?;
    if end > data.len() {
        return Err(Error::buffer_too_short(end, data.len()));
    }
    Ok((&data[content..end], end))
}
