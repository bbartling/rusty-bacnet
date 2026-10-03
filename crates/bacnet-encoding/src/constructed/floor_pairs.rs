//! The framed list of floor pairs that `BACnetLandingDoorStatus` and
//! `BACnetAssignedLandingCalls` share (Clause 21).
//!
//! Each of the two productions holds one member, context tag 0, which frames
//! a list with opening and closing tag 0. Every entry of that list is two
//! primitive context tags in a fixed order: the universal floor number `[0]`
//! (Unsigned8), then a BACnet enumeration `[1]` (a door status, or a car
//! direction). An empty list encodes as the bare frame.

use bacnet_types::error::Error;
use bytes::BytesMut;

use super::members::{member_content, narrow, unsigned_member};
use super::MAX_FRAMED_ITEMS;
use crate::primitives;
use crate::tags;

/// How one production names its parts in decode errors.
pub(super) struct PairNames {
    /// The production, e.g. "landing door status".
    pub(super) value: &'static str,
    /// The framed member, e.g. "landing-doors \[0\]".
    pub(super) frame: &'static str,
    /// One list entry, e.g. "landing door".
    pub(super) entry: &'static str,
    /// The enumerated member, e.g. "door-status \[1\]".
    pub(super) second: &'static str,
    /// The range error for an oversized enumerated member, e.g.
    /// "door-status \[1\] exceeds 32 bits".
    pub(super) second_oversized: &'static str,
}

/// Encode the frame around `pairs`, each a floor number and the raw value of
/// its enumerated member.
pub(super) fn encode_floor_pairs(buf: &mut BytesMut, pairs: impl IntoIterator<Item = (u8, u32)>) {
    tags::encode_opening_tag(buf, 0);
    for (floor, value) in pairs {
        primitives::encode_ctx_unsigned(buf, 0, floor.into());
        primitives::encode_ctx_enumerated(buf, 1, value);
    }
    tags::encode_closing_tag(buf, 0);
}

/// Decode the frame at `offset` into its floor number and enumerated value
/// pairs, and return them with the offset just past the closing tag.
///
/// Two kinds of failure are kept apart, so a property writer can answer with
/// the matching Clause 15.9.1.3 error. A malformed value (a missing frame or
/// member, an empty or truncated member, or more than 10,000 entries) fails
/// with [`Error::Decoding`] or [`Error::BufferTooShort`]. A value that is
/// well formed throughout, but where a floor number exceeds an Unsigned8 or
/// an enumerated member exceeds 32 bits, fails with [`Error::OutOfRange`]
/// naming the first oversized member. A malformed member anywhere in the
/// value takes precedence over an oversized one.
pub(super) fn decode_floor_pairs(
    data: &[u8],
    offset: usize,
    names: &PairNames,
) -> Result<(Vec<(u8, u32)>, usize), Error> {
    let mut oversized = None;
    let (tag, mut offset) = tags::decode_tag(data, offset)?;
    if !tag.is_opening_tag(0) {
        return Err(Error::decoding(
            offset,
            format!("{} requires {}", names.value, names.frame),
        ));
    }
    let mut pairs = Vec::new();
    loop {
        let (tag, content) = tags::decode_tag(data, offset)?;
        if tag.is_closing_tag(0) {
            if let Some(member) = oversized {
                return Err(Error::OutOfRange(format!("{} {member}", names.value)));
            }
            return Ok((pairs, content));
        }
        if pairs.len() >= MAX_FRAMED_ITEMS {
            return Err(Error::decoding(
                offset,
                format!("{} exceeds the decoded item limit", names.value),
            ));
        }
        if !tag.is_context(0) {
            return Err(Error::decoding(
                offset,
                format!("{} requires floor-number [0]", names.entry),
            ));
        }
        let (floor, next) = member_content(data, content, tag.length)?;
        let floor_number = narrow(
            unsigned_member(floor, content)?,
            "floor-number [0] exceeds an Unsigned8",
            &mut oversized,
        );

        let (tag, content) = tags::decode_tag(data, next)?;
        if !tag.is_context(1) {
            return Err(Error::decoding(
                next,
                format!("{} requires {}", names.entry, names.second),
            ));
        }
        let (raw, next) = member_content(data, content, tag.length)?;
        let value: u32 = narrow(
            unsigned_member(raw, content)?,
            names.second_oversized,
            &mut oversized,
        );

        pairs.push((floor_number, value));
        offset = next;
    }
}
