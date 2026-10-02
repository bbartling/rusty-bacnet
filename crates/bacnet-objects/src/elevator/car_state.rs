//! Car_Assigned_Direction, Car_Door_Zone, Car_Mode, Next_Stopping_Floor and
//! Car_Drive_Status: the single-valued Lift rows (Clause 12.59, Table 12-77)
//! that describe what the car is doing and where it goes next.
//!
//! The application owns all five in service, setting them through
//! `LiftObject` setters, and they are read-only over the network. Items (c)
//! and (d) of the Lift's Out_Of_Service description open them to writes
//! while Out_Of_Service is TRUE, so a test tool can simulate the car; in
//! service a write is refused with WRITE_ACCESS_DENIED. A write of the
//! wrong datatype is INVALID_DATA_TYPE. A Next_Stopping_Floor above 255, or
//! an enumeration value outside its type's named values and the 1024..=65535
//! proprietary range (Clause 23.1, Table 23-1), is VALUE_OUT_OF_RANGE. A
//! refused write changes nothing.

use bacnet_types::enums::{LiftCarDirection, LiftCarDriveStatus, LiftCarMode, PropertyIdentifier};
use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;

use super::{checked, direction_in_range, named_or_proprietary};
use crate::common;

/// What one lift car is doing and where it stops next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CarState {
    /// Car_Assigned_Direction: the direction the car is assigned to move.
    pub(super) assigned_direction: LiftCarDirection,
    /// Car_Door_Zone: whether the car is where its doors may start opening.
    pub(super) door_zone: bool,
    /// Car_Mode: the car's operating mode.
    pub(super) mode: LiftCarMode,
    /// Next_Stopping_Floor: the floor of the car's next stop, or the floor it
    /// stands at while it isn't moving (Unsigned8, universal numbering).
    pub(super) next_stopping_floor: u8,
    /// Car_Drive_Status: the state of the car's motor drive.
    pub(super) drive_status: LiftCarDriveStatus,
}

/// Whether `mode` is in BACnetLiftCarMode.
pub(super) fn mode_in_range(mode: &LiftCarMode) -> bool {
    named_or_proprietary(LiftCarMode::ALL_NAMED, *mode, mode.to_raw())
}

/// Whether `status` is in BACnetLiftCarDriveStatus.
pub(super) fn drive_status_in_range(status: &LiftCarDriveStatus) -> bool {
    named_or_proprietary(LiftCarDriveStatus::ALL_NAMED, *status, status.to_raw())
}

impl CarState {
    /// A car the application hasn't described yet: direction, mode and drive
    /// status UNKNOWN, outside the door zone, and stopping next at floor 1,
    /// where a new Lift's car stands.
    pub(super) fn new() -> Self {
        Self {
            assigned_direction: LiftCarDirection::UNKNOWN,
            door_zone: false,
            mode: LiftCarMode::UNKNOWN,
            next_stopping_floor: 1,
            drive_status: LiftCarDriveStatus::UNKNOWN,
        }
    }

    /// The value of `property` if it is one of the five rows.
    pub(super) fn read(&self, property: PropertyIdentifier) -> Option<PropertyValue> {
        Some(match property {
            PropertyIdentifier::CAR_ASSIGNED_DIRECTION => {
                PropertyValue::Enumerated(self.assigned_direction.to_raw())
            }
            PropertyIdentifier::CAR_DOOR_ZONE => PropertyValue::Boolean(self.door_zone),
            PropertyIdentifier::CAR_MODE => PropertyValue::Enumerated(self.mode.to_raw()),
            PropertyIdentifier::NEXT_STOPPING_FLOOR => {
                PropertyValue::Unsigned(self.next_stopping_floor.into())
            }
            PropertyIdentifier::CAR_DRIVE_STATUS => {
                PropertyValue::Enumerated(self.drive_status.to_raw())
            }
            _ => return None,
        })
    }

    /// Handle a WriteProperty on one of the five rows; `None` for any other
    /// property.
    pub(super) fn write(
        &mut self,
        property: PropertyIdentifier,
        value: &PropertyValue,
        out_of_service: bool,
    ) -> Option<Result<(), Error>> {
        self.read(property)?;
        if !out_of_service {
            return Some(Err(common::write_access_denied_error()));
        }
        Some(self.store(property, value))
    }

    fn store(&mut self, property: PropertyIdentifier, value: &PropertyValue) -> Result<(), Error> {
        match (property, value) {
            (PropertyIdentifier::CAR_ASSIGNED_DIRECTION, &PropertyValue::Enumerated(raw)) => {
                self.assigned_direction =
                    checked(LiftCarDirection::from_raw(raw), direction_in_range)?;
            }
            (PropertyIdentifier::CAR_DOOR_ZONE, &PropertyValue::Boolean(zone)) => {
                self.door_zone = zone;
            }
            (PropertyIdentifier::CAR_MODE, &PropertyValue::Enumerated(raw)) => {
                self.mode = checked(LiftCarMode::from_raw(raw), mode_in_range)?;
            }
            (PropertyIdentifier::NEXT_STOPPING_FLOOR, &PropertyValue::Unsigned(floor)) => {
                self.next_stopping_floor =
                    u8::try_from(floor).map_err(|_| common::value_out_of_range_error())?;
            }
            (PropertyIdentifier::CAR_DRIVE_STATUS, &PropertyValue::Enumerated(raw)) => {
                self.drive_status =
                    checked(LiftCarDriveStatus::from_raw(raw), drive_status_in_range)?;
            }
            _ => return Err(common::invalid_data_type_error()),
        }
        Ok(())
    }
}
