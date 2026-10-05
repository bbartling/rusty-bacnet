//! Shared BACnet service data types per ASHRAE 135-2020 Clause 21.

pub use bacnet_types::constructed::BACnetPropertyValue;

/// Safety limit for decoded sequences to prevent unbounded allocations.
pub const MAX_DECODED_ITEMS: usize = 10_000;

pub(crate) mod error_type;
