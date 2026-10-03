//! Encode and decode a Notification Forwarder's Port_Filter elements (Clause
//! 12.51.11, Clause 21 BACnetPortPermission).
//!
//! Each element is a bare sequence of two required context-tagged members:
//! `[0]` the port ID (Unsigned8) and `[1]` the enabled flag. The array's
//! elements follow one another with no wrapper, so the decoder reads one
//! element at `offset` and returns the offset just past it.

use bacnet_types::constructed::BACnetPortPermission;
use bacnet_types::error::Error;
use bytes::BytesMut;

use crate::primitives;

use super::tagged::{decode_ctx_boolean, decode_ctx_unsigned};

/// Encode one bare `BACnetPortPermission` sequence.
pub fn encode_port_permission(buf: &mut BytesMut, permission: &BACnetPortPermission) {
    primitives::encode_ctx_unsigned(buf, 0, u64::from(permission.port_id));
    primitives::encode_ctx_boolean(buf, 1, permission.enabled);
}

/// Decode one bare `BACnetPortPermission` at `offset`; returns it and the
/// offset past its `[1]` member. A missing member, a port ID past Unsigned8
/// or a BOOLEAN other than 0 or 1 is a decode error.
pub fn decode_port_permission(
    data: &[u8],
    offset: usize,
) -> Result<(BACnetPortPermission, usize), Error> {
    let what = "BACnetPortPermission";
    let (port_id, pos) = decode_ctx_unsigned::<u8>(data, offset, 0, what)?;
    let (enabled, pos) = decode_ctx_boolean(data, pos, 1, what)?;
    Ok((BACnetPortPermission { port_id, enabled }, pos))
}
