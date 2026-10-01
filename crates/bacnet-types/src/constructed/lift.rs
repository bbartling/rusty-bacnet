//! Constructed values used by the Elevator Group object (Clause 12.58).

#[cfg(not(feature = "std"))]
use alloc::string::String;

use crate::enums::LiftCarDirection;

/// The `command` CHOICE of a [`BACnetLandingCallStatus`] (Clause 21).
///
/// A landing call asks either for a direction of travel or for a destination
/// floor. The CHOICE is untagged inside the SEQUENCE, so each alternative's
/// own context tag appears directly on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LandingCallCommand {
    /// Context tag 1: the direction the caller wants to travel.
    ///
    /// Decoding keeps any value, including reserved and proprietary ones;
    /// whoever accepts a write decides which values are in range.
    Direction(LiftCarDirection),
    /// Context tag 2: the destination floor the caller selected (Unsigned8).
    Destination(u8),
}

/// `BACnetLandingCallStatus` (Clause 21): one call placed at a landing.
///
/// The Elevator Group object serves this as Landing_Call_Control and as each
/// element of its Landing_Calls list (Clause 12.58, Table 12-76). The
/// `bacnet-encoding` crate owns the wire codec.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BACnetLandingCallStatus {
    /// Context tag 0: the floor where the call was placed (Unsigned8).
    pub floor_number: u8,
    /// Context tags 1 and 2: the requested direction or destination floor.
    pub command: LandingCallCommand,
    /// Context tag 3, optional: a label for the floor.
    pub floor_text: Option<String>,
}
