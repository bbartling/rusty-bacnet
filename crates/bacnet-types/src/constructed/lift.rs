//! Constructed values used by the Elevator Group (Clause 12.58) and Lift
//! (Clause 12.59) objects.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::enums::{DoorStatus, LiftCarDirection};

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

/// One landing door in a [`BACnetLandingDoorStatus`]: the floor it serves
/// and its current status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LandingDoor {
    /// Context tag 0: the universal floor number of the landing (Unsigned8).
    pub floor_number: u8,
    /// Context tag 1: the landing door's status.
    ///
    /// Decoding keeps any value, including reserved and proprietary ones;
    /// whoever stores the value decides which ones are in range.
    pub door_status: DoorStatus,
}

/// `BACnetLandingDoorStatus` (Clause 21): the landing doors that pair with one
/// car door, floor by floor.
///
/// The Lift object serves an array of these as Landing_Door_Status, one
/// element per car door (Clause 12.59, Table 12-77). The `bacnet-encoding`
/// crate owns the wire codec.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct BACnetLandingDoorStatus {
    /// Context tag 0: the landing doors, in the order they are encoded.
    pub landing_doors: Vec<LandingDoor>,
}

/// One landing call in a [`BACnetAssignedLandingCalls`]: the floor it was
/// placed at and the direction it asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssignedLandingCall {
    /// Context tag 0: the landing's floor, by universal floor number
    /// (Unsigned8).
    pub floor_number: u8,
    /// Context tag 1: the direction of travel the call asks for.
    ///
    /// Decoding keeps any value, including reserved and proprietary ones;
    /// whoever stores the value decides which ones are in range.
    pub direction: LiftCarDirection,
}

/// `BACnetAssignedLandingCalls` (Clause 21): the landing calls assigned to
/// one car door.
///
/// The Lift object serves an array of these as Assigned_Landing_Calls, one
/// element per car door (Clause 12.59, Table 12-77). The `bacnet-encoding`
/// crate owns the wire codec.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct BACnetAssignedLandingCalls {
    /// Context tag 0: the landing calls, in the order they are encoded.
    pub landing_calls: Vec<AssignedLandingCall>,
}

/// `BACnetLiftCarCallList` (Clause 21): the floors with a car call registered
/// for one car door.
///
/// The Lift object serves an array of these as Registered_Car_Call, one
/// element per car door (Clause 12.59, Table 12-77). The `bacnet-encoding`
/// crate owns the wire codec.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct BACnetLiftCarCallList {
    /// Context tag 0: the universal floor numbers (each an Unsigned8), in the
    /// order they are encoded.
    pub floor_numbers: Vec<u8>,
}
