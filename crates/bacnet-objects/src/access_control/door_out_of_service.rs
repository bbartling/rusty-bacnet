//! Door_Status, Lock_Status and Door_Alarm_State while Out_Of_Service is TRUE
//! (Clauses 12.26.9, 12.26.12, 12.26.13 and 12.26.20, Table 12-30 footnote 1,
//! #1131).
//!
//! Footnote 1 of Table 12-30 marks exactly these three rows, so a client can
//! simulate the door by writing them. The door takes WriteProperty and
//! WritePropertyMultiple of the three only while Out_Of_Service is TRUE and
//! refuses them with WRITE_ACCESS_DENIED in service. Each write has to be an
//! Enumerated inside its Clause 21 production: a named BACnetDoorStatus or
//! one from the proprietary range 1024..=65535, a named BACnetLockStatus (the
//! production is closed and Table 23-1 doesn't list it, so it has no
//! proprietary range), or a named BACnetDoorAlarmState or one from
//! 256..=65535. Any other number is VALUE_OUT_OF_RANGE and any other datatype
//! INVALID_DATA_TYPE, with the property left as it was.
//!
//! Reliability isn't among the footnoted rows. Clause 12.26.9 asks for it to be
//! writable only on a door whose Reliability can leave NO_FAULT_DETECTED, and
//! this door runs no fault algorithm and has no route that changes it, so it
//! stays read-only. Present_Value is commandable in both states already.
//!
//! Clause 12.26.20 keeps Door_Alarm_State to NORMAL plus the members of
//! Alarm_Values and Fault_Values, and out of Masked_Alarm_Values. The door
//! serves none of the three lists, so a simulated value is checked against
//! the enumeration alone.
//!
//! Out of service the three values stop following the device, so the door
//! keeps the device's own values to one side:
//!
//! - On the FALSE-to-TRUE edge it puts aside the three values it serves
//!   (`common::write_out_of_service_with_restore`).
//! - Meanwhile a value the application reports (`set_door_status`,
//!   `set_lock_status`, `set_door_alarm_state`) replaces the value put aside,
//!   not the one served.
//! - On the TRUE-to-FALSE edge all three go back to the values put aside, so
//!   the device's state is served again at once and the simulated values are
//!   gone.
//!
//! How a simulated value reaches the rest of the door and the server:
//!
//! - COV: Door_Alarm_State is a trigger of the Access Door row of Table 13-1
//!   (#1061), and the server compares the row's values around every committed
//!   write, so a simulated Door_Alarm_State sends a SubscribeCOV report, as the
//!   return to service does when it restores a different value. Door_Status
//!   and Lock_Status aren't in that row and send none by themselves.
//! - Pulse relock: Door_Pulse_Time and Door_Extended_Pulse_Time relinquish a
//!   pulse from the priority array on a timer armed by the command (#1073).
//!   Nothing reads Door_Status, Lock_Status or Door_Alarm_State to relinquish
//!   early or to hold the slot, so a simulated value neither drives nor delays
//!   the relock, and the relock leaves the simulated values alone.
//! - Event reporting: the door runs no intrinsic reporting (no
//!   CHANGE_OF_STATE algorithm; Event_State stays NORMAL), so a simulated
//!   Door_Alarm_State raises no event of its own. An Event Enrollment that
//!   monitors the property reads the served value, so it sees the simulation
//!   as it would see the device.
//! - Secured_Status is stored, not derived from these values, so a simulation
//!   doesn't move it.

use bacnet_types::enums::{DoorAlarmState, DoorStatus, LockStatus, PropertyIdentifier};
use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;

use crate::common;

/// The door state a client can simulate while Out_Of_Service is TRUE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DoorState {
    pub(super) door_status: DoorStatus,
    pub(super) lock_status: LockStatus,
    pub(super) door_alarm_state: DoorAlarmState,
}

impl DoorState {
    /// A closed, locked door with no alarm.
    pub(super) const SECURE: Self = Self {
        door_status: DoorStatus::CLOSED,
        lock_status: LockStatus::LOCKED,
        door_alarm_state: DoorAlarmState::NORMAL,
    };

    /// Apply a client's write of Door_Status, Lock_Status or
    /// Door_Alarm_State, taken only while `out_of_service`; `None` for any
    /// other property.
    pub(super) fn write(
        &mut self,
        out_of_service: bool,
        property: PropertyIdentifier,
        value: &PropertyValue,
    ) -> Option<Result<(), Error>> {
        let apply: fn(&mut Self, u32) -> Result<(), Error> = match property {
            p if p == PropertyIdentifier::DOOR_STATUS => |state, raw| {
                state.door_status = checked(DoorStatus::from_raw(raw), door_status_in_range)?;
                Ok(())
            },
            p if p == PropertyIdentifier::LOCK_STATUS => |state, raw| {
                state.lock_status = checked(LockStatus::from_raw(raw), lock_status_in_range)?;
                Ok(())
            },
            p if p == PropertyIdentifier::DOOR_ALARM_STATE => |state, raw| {
                state.door_alarm_state =
                    checked(DoorAlarmState::from_raw(raw), door_alarm_state_in_range)?;
                Ok(())
            },
            _ => return None,
        };
        if !out_of_service {
            return Some(Err(common::write_access_denied_error()));
        }
        let PropertyValue::Enumerated(raw) = value else {
            return Some(Err(common::invalid_data_type_error()));
        };
        Some(apply(self, *raw))
    }
}

/// `value`, or VALUE_OUT_OF_RANGE when `in_range` refuses it.
fn checked<T: Copy>(value: T, in_range: fn(T) -> bool) -> Result<T, Error> {
    if in_range(value) {
        Ok(value)
    } else {
        Err(common::value_out_of_range_error())
    }
}

/// Whether `status` is a named BACnetDoorStatus or a proprietary one
/// (1024..=65535, Clause 23.1).
fn door_status_in_range(status: DoorStatus) -> bool {
    DoorStatus::ALL_NAMED
        .iter()
        .any(|&(_, named)| named == status)
        || (1024..=65_535).contains(&status.to_raw())
}

/// Whether `status` is a named BACnetLockStatus, a closed production.
fn lock_status_in_range(status: LockStatus) -> bool {
    LockStatus::ALL_NAMED
        .iter()
        .any(|&(_, named)| named == status)
}

/// Whether `state` is a named BACnetDoorAlarmState or a proprietary one
/// (256..=65535, Clause 23.1).
fn door_alarm_state_in_range(state: DoorAlarmState) -> bool {
    DoorAlarmState::ALL_NAMED
        .iter()
        .any(|&(_, named)| named == state)
        || (256..=65_535).contains(&state.to_raw())
}
