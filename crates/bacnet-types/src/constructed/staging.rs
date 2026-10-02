//! Constructed values used by the Staging object.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// One entry in a Staging object's `Stages` array.
///
/// On the wire (`BACnetStageLimitValue`, Clause 21) the three fields go out
/// application-tagged in declaration order: the limit as a REAL, the values
/// as a BIT STRING, then the deadband as a REAL. `values` stores the logical bits in
/// target-reference order; the encoding crate owns their MSB-first packing.
#[derive(Debug, Clone, PartialEq)]
pub struct BACnetStageLimitValue {
    /// The nominal upper limit for this stage.
    pub limit: f32,
    /// One ACTIVE (`true`) or INACTIVE (`false`) value per target reference.
    pub values: Vec<bool>,
    /// The nonnegative hysteresis deadband around this limit.
    pub deadband: f32,
}
