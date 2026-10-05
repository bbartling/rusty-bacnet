//! Clause 21 codecs for an Accumulator's Scale and Prescale (Clause 12.61,
//! Table 12-79).
//!
//! - `BACnetScale` is a CHOICE of two primitive context tags: `[0]` a REAL
//!   for a float scale, `[1]` an INTEGER for a power-of-ten scale. A value is
//!   that one tag, with no frame around it.
//! - `BACnetPrescale` is a SEQUENCE of two required primitive context tags:
//!   `[0]` the multiplier and `[1]` the modulo divide, both Unsigned.

use bacnet_types::constructed::{BACnetPrescale, BACnetScale};
use bacnet_types::error::Error;
use bytes::BytesMut;

use super::tagged::{decode_ctx_primitive, decode_ctx_real, decode_ctx_unsigned};
use crate::{primitives, tags};

const SCALE: &str = "BACnetScale";
const PRESCALE: &str = "BACnetPrescale";

/// Encode one `BACnetScale` CHOICE, appending to `buf`.
pub fn encode_scale(buf: &mut BytesMut, scale: &BACnetScale) {
    match *scale {
        BACnetScale::FloatScale(factor) => primitives::encode_ctx_real(buf, 0, factor),
        BACnetScale::IntegerScale(power) => primitives::encode_ctx_signed(buf, 1, power),
    }
}

/// Decode one `BACnetScale` CHOICE at `offset`.
///
/// Returns the scale and the offset just past it; a caller holding exactly
/// one value must check that offset reaches the end of its data. Any tag but
/// a primitive context `[0]` or `[1]`, a REAL that isn't four octets, an
/// INTEGER of no octets or more than four, or truncated contents fails with
/// [`Error::Decoding`] or [`Error::BufferTooShort`].
pub fn decode_scale(data: &[u8], offset: usize) -> Result<(BACnetScale, usize), Error> {
    let (tag, _) = tags::decode_tag(data, offset)?;
    if tag.is_context(0) {
        let (factor, end) = decode_ctx_real(data, offset, 0, SCALE)?;
        return Ok((BACnetScale::FloatScale(factor), end));
    }
    if tag.is_context(1) {
        let (octets, end) = decode_ctx_primitive(data, offset, 1, SCALE)?;
        let power = primitives::decode_signed(octets).map_err(|_| {
            Error::decoding(
                offset,
                format!("{SCALE}: integer-scale [1] needs 1 to 4 octets"),
            )
        })?;
        return Ok((BACnetScale::IntegerScale(power), end));
    }
    Err(Error::decoding(
        offset,
        format!("{SCALE}: expected float-scale [0] or integer-scale [1]"),
    ))
}

/// Encode one `BACnetPrescale` SEQUENCE, appending to `buf`.
pub fn encode_prescale(buf: &mut BytesMut, prescale: &BACnetPrescale) {
    primitives::encode_ctx_unsigned(buf, 0, u64::from(prescale.multiplier));
    primitives::encode_ctx_unsigned(buf, 1, u64::from(prescale.modulo_divide));
}

/// Decode one `BACnetPrescale` SEQUENCE at `offset`; returns it and the
/// offset past its `[1]` member. A missing member, members out of order or a
/// value past unsigned32, the width the object keeps, is a decode error.
pub fn decode_prescale(data: &[u8], offset: usize) -> Result<(BACnetPrescale, usize), Error> {
    let (multiplier, pos) = decode_ctx_unsigned::<u32>(data, offset, 0, PRESCALE)?;
    let (modulo_divide, end) = decode_ctx_unsigned::<u32>(data, pos, 1, PRESCALE)?;
    Ok((
        BACnetPrescale {
            multiplier,
            modulo_divide,
        },
        end,
    ))
}
