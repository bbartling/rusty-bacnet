//! Clause 21 codec for `BACnetAccessRule`, the element of an Access Rights
//! object's Positive_Access_Rules and Negative_Access_Rules arrays (Clause
//! 12.34.9.1).
//!
//! A rule is a bare SEQUENCE and a whole array concatenates them with no
//! wrapper, so the decoder reads one rule at `offset` and returns the offset
//! just past it, the way the Access Credential element codecs do.
//!
//! The decoder checks structure only. It keeps each specifier as received,
//! a value outside the two named ones included, and doesn't compare a
//! specifier with the presence of its reference; the Access Rights object
//! judges both. A specifier wider than 32 bits is malformed.

use bacnet_types::constructed::BACnetAccessRule;
use bacnet_types::enums::{AccessRuleLocationSpecifier, AccessRuleTimeRangeSpecifier};
use bacnet_types::error::Error;
use bytes::BytesMut;

use super::tagged::{
    decode_ctx_boolean, decode_ctx_unsigned, expect_closing, expect_opening, next_is_opening,
};
use super::{
    decode_device_object_reference, decode_dopr_body, encode_device_object_reference,
    encode_dopr_body,
};
use crate::{primitives, tags};

const RULE: &str = "BACnetAccessRule";

/// Encode one `BACnetAccessRule` SEQUENCE: the time-range specifier as
/// context `[0]`, the time-range reference (when present) inside opening and
/// closing tag 1, the location specifier as context `[2]`, the location
/// reference (when present) inside opening and closing tag 3, and the enable
/// flag as context `[4]`.
pub fn encode_access_rule(buf: &mut BytesMut, rule: &BACnetAccessRule) {
    primitives::encode_ctx_enumerated(buf, 0, rule.time_range_specifier.to_raw());
    if let Some(time_range) = &rule.time_range {
        tags::encode_opening_tag(buf, 1);
        encode_dopr_body(buf, time_range);
        tags::encode_closing_tag(buf, 1);
    }
    primitives::encode_ctx_enumerated(buf, 2, rule.location_specifier.to_raw());
    if let Some(location) = &rule.location {
        tags::encode_opening_tag(buf, 3);
        encode_device_object_reference(buf, location);
        tags::encode_closing_tag(buf, 3);
    }
    primitives::encode_ctx_boolean(buf, 4, rule.enable);
}

/// Decode one `BACnetAccessRule` SEQUENCE at `offset`.
///
/// A missing specifier or enable flag, members out of order, a reference
/// frame that doesn't close right after one reference, a truncated member
/// or a BOOLEAN whose contents aren't 0 or 1 fails with [`Error::Decoding`]
/// or [`Error::BufferTooShort`].
pub fn decode_access_rule(data: &[u8], offset: usize) -> Result<(BACnetAccessRule, usize), Error> {
    let (time_range_specifier, mut pos) = decode_ctx_unsigned::<u32>(data, offset, 0, RULE)?;
    let time_range = if next_is_opening(data, pos, 1)? {
        let content = expect_opening(data, pos, 1, RULE)?;
        let (reference, end) = decode_dopr_body(data, content, RULE)?;
        pos = expect_closing(data, end, 1, RULE)?;
        Some(reference)
    } else {
        None
    };
    let (location_specifier, mut pos) = decode_ctx_unsigned::<u32>(data, pos, 2, RULE)?;
    let location = if next_is_opening(data, pos, 3)? {
        let content = expect_opening(data, pos, 3, RULE)?;
        let (reference, end) = decode_device_object_reference(data, content)?;
        pos = expect_closing(data, end, 3, RULE)?;
        Some(reference)
    } else {
        None
    };
    let (enable, end) = decode_ctx_boolean(data, pos, 4, RULE)?;
    Ok((
        BACnetAccessRule {
            time_range_specifier: AccessRuleTimeRangeSpecifier::from_raw(time_range_specifier),
            time_range,
            location_specifier: AccessRuleLocationSpecifier::from_raw(location_specifier),
            location,
            enable,
        },
        end,
    ))
}
