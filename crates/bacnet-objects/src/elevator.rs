//! Elevator Group, Escalator, and Lift objects per ASHRAE 135-2020.
//!
//! - ElevatorGroupObject (type 57) — Clause 12.58
//! - EscalatorObject (type 58) — Clause 12.60
//! - LiftObject (type 59) — Clause 12.59

use bacnet_types::constructed::BACnetLandingCallStatus;
use bacnet_types::enums::{
    EscalatorFault, EscalatorMode, EscalatorOperationDirection, LiftCarDirection, LiftGroupMode,
    ObjectType, PropertyIdentifier, Reliability,
};
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue, StatusFlags};
use std::{borrow::Cow, collections::HashSet};

use crate::common::{self, read_common_properties};
use crate::traits::BACnetObject;

mod landing_calls;
mod metadata;

/// Whether `raw` is in the domain of one of this family's extensible Clause 21
/// enumerations: one of its named values (`named` is its `ALL_NAMED` table,
/// `value` is `raw` as that type), or the proprietary range 1024..=65535 that
/// Clause 23.1 (Table 23-1) opens for each of them. Every other value is
/// reserved or too large, and a write of it is refused with
/// VALUE_OUT_OF_RANGE.
fn named_or_proprietary<T: Copy + PartialEq>(named: &[(&str, T)], value: T, raw: u32) -> bool {
    named.iter().any(|&(_, named)| named == value) || (1024..=65_535).contains(&raw)
}

// ===========================================================================
// ElevatorGroupObject (type 57)
// ===========================================================================

/// BACnet Elevator Group object — manages a group of lifts.
///
/// The object serves only properties its table (Clause 12.58, Table 12-76)
/// defines. That table has no Status_Flags, Out_Of_Service or Reliability, so
/// reads and writes of those return UNKNOWN_PROPERTY.
pub struct ElevatorGroupObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    /// The Positive Integer Value object holding the machine room's number.
    machine_room_id: ObjectIdentifier,
    /// Group identifier (Unsigned8).
    group_id: u8,
    /// List of lift ObjectIdentifiers in this group.
    group_members: Vec<ObjectIdentifier>,
    /// Group mode.
    group_mode: LiftGroupMode,
    /// Active landing calls, served as the Landing_Calls BACnetLIST.
    landing_calls: Vec<BACnetLandingCallStatus>,
    /// The last call written to Landing_Call_Control.
    landing_call_control: BACnetLandingCallStatus,
}

impl ElevatorGroupObject {
    /// Create a new Elevator Group object with default values.
    pub fn new(instance: u32, name: impl Into<String>) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::ELEVATOR_GROUP, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            machine_room_id: ObjectIdentifier::new(
                ObjectType::POSITIVE_INTEGER_VALUE,
                ObjectIdentifier::MAX_INSTANCE,
            )?,
            group_id: 0,
            group_members: Vec::new(),
            group_mode: LiftGroupMode::UNKNOWN,
            landing_calls: Vec::new(),
            landing_call_control: landing_calls::initial_landing_call_control(),
        })
    }

    /// The Positive Integer Value object served as Machine_Room_ID. Until the
    /// application sets one it names instance 4194303, which Clause 12.58
    /// uses when the machine room has no identification number.
    pub fn machine_room_id(&self) -> ObjectIdentifier {
        self.machine_room_id
    }

    /// Set the Positive Integer Value object whose Present_Value holds the
    /// number of the machine room this group is in (Clause 12.58).
    ///
    /// Machine_Room_ID is read-only over the network, so this is the only way
    /// to change it. A reference to any other object type is refused with
    /// VALUE_OUT_OF_RANGE and the property is left unchanged.
    pub fn set_machine_room_id(&mut self, oid: ObjectIdentifier) -> Result<(), Error> {
        if oid.object_type() != ObjectType::POSITIVE_INTEGER_VALUE {
            return Err(common::value_out_of_range_error());
        }
        self.machine_room_id = oid;
        Ok(())
    }

    /// Add a lift member to this elevator group.
    pub fn add_member(&mut self, oid: ObjectIdentifier) {
        self.group_members.push(oid);
    }

    /// The last landing call written to Landing_Call_Control, or a placeholder
    /// of floor 0 with direction UNKNOWN before any write.
    pub fn landing_call_control(&self) -> &BACnetLandingCallStatus {
        &self.landing_call_control
    }

    /// The active landing calls served as Landing_Calls.
    pub fn landing_calls(&self) -> &[BACnetLandingCallStatus] {
        &self.landing_calls
    }

    /// Replace the active landing calls served as Landing_Calls.
    ///
    /// The application owns this list: a Landing_Call_Control write doesn't
    /// add to it. A call with a direction outside BACnetLiftCarDirection is
    /// refused with VALUE_OUT_OF_RANGE and the list is left unchanged.
    pub fn set_landing_calls(&mut self, calls: Vec<BACnetLandingCallStatus>) -> Result<(), Error> {
        calls.iter().try_for_each(landing_calls::validate)?;
        self.landing_calls = calls;
        Ok(())
    }
}

impl BACnetObject for ElevatorGroupObject {
    fn object_identifier(&self) -> ObjectIdentifier {
        self.oid
    }

    fn object_name(&self) -> &str {
        &self.name
    }

    fn read_property(
        &self,
        property: PropertyIdentifier,
        array_index: Option<u32>,
    ) -> Result<PropertyValue, Error> {
        // No read_common_properties!: it would serve Status_Flags,
        // Out_Of_Service and Reliability, which Table 12-76 doesn't define.
        match property {
            p if p == PropertyIdentifier::OBJECT_IDENTIFIER => {
                Ok(PropertyValue::ObjectIdentifier(self.oid))
            }
            p if p == PropertyIdentifier::OBJECT_NAME => {
                Ok(PropertyValue::CharacterString(self.name.clone()))
            }
            p if p == PropertyIdentifier::DESCRIPTION => {
                Ok(PropertyValue::CharacterString(self.description.clone()))
            }
            p if p == PropertyIdentifier::OBJECT_TYPE => Ok(PropertyValue::Enumerated(
                ObjectType::ELEVATOR_GROUP.to_raw(),
            )),
            p if p == PropertyIdentifier::PROPERTY_LIST => {
                common::read_property_list_property(&self.property_list(), array_index)
            }
            p if p == PropertyIdentifier::MACHINE_ROOM_ID => {
                Ok(PropertyValue::ObjectIdentifier(self.machine_room_id))
            }
            p if p == PropertyIdentifier::GROUP_ID => {
                Ok(PropertyValue::Unsigned(u64::from(self.group_id)))
            }
            p if p == PropertyIdentifier::GROUP_MEMBERS => {
                let items: Vec<PropertyValue> = self
                    .group_members
                    .iter()
                    .map(|oid| PropertyValue::ObjectIdentifier(*oid))
                    .collect();
                Ok(PropertyValue::List(items))
            }
            p if p == PropertyIdentifier::GROUP_MODE => {
                Ok(PropertyValue::Enumerated(self.group_mode.to_raw()))
            }
            p if p == PropertyIdentifier::LANDING_CALLS => Ok(PropertyValue::List(
                self.landing_calls
                    .iter()
                    .map(landing_calls::encode)
                    .collect::<Result<Vec<_>, Error>>()?,
            )),
            p if p == PropertyIdentifier::LANDING_CALL_CONTROL => {
                landing_calls::encode(&self.landing_call_control)
            }
            _ => Err(common::unknown_property_error()),
        }
    }

    fn write_property(
        &mut self,
        property: PropertyIdentifier,
        _array_index: Option<u32>,
        value: PropertyValue,
        _priority: Option<u8>,
    ) -> Result<(), Error> {
        if let Some(result) = common::write_description(&mut self.description, property, &value) {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::GROUP_ID => {
                if let PropertyValue::Unsigned(v) = value {
                    // Group_ID is an Unsigned8 (Table 12-76).
                    self.group_id =
                        u8::try_from(v).map_err(|_| common::value_out_of_range_error())?;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            p if p == PropertyIdentifier::GROUP_MODE => {
                if let PropertyValue::Enumerated(v) = value {
                    self.group_mode = LiftGroupMode::from_raw(v);
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            p if p == PropertyIdentifier::LANDING_CALL_CONTROL => {
                self.landing_call_control = landing_calls::decode_write(value)?;
                Ok(())
            }
            _ => Err(crate::common::unhandled_write_error(
                self.property_metadata().as_ref(),
                property,
                _array_index,
            )),
        }
    }

    fn property_metadata(&self) -> Cow<'_, [crate::property_metadata::PropertyMetadata]> {
        metadata::for_elevator_group_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }
}

// ===========================================================================
// EscalatorObject (type 58)
// ===========================================================================

/// BACnet Escalator object — represents an escalator.
pub struct EscalatorObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    /// Escalator mode (BACnetEscalatorMode, Clause 21); proprietary extensions
    /// (Clause 23.1) are preserved as raw values.
    escalator_mode: EscalatorMode,
    /// Fault signal set (BACnetEscalatorFault, Clause 21).
    fault_signals: Vec<EscalatorFault>,
    /// Energy meter reading (Real).
    energy_meter: f32,
    /// Energy meter reference (stored as raw bytes).
    energy_meter_ref: Vec<u8>,
    /// Power mode (Boolean).
    power_mode: bool,
    /// Operation direction (BACnetEscalatorOperationDirection, Clause 21);
    /// proprietary extensions (Clause 23.1) are preserved as raw values.
    operation_direction: EscalatorOperationDirection,
    /// Passenger alarm state (Boolean).
    passenger_alarm: bool,
    status_flags: StatusFlags,
    out_of_service: bool,
    reliability: Reliability,
}

impl EscalatorObject {
    /// Create a new Escalator object with default values.
    pub fn new(instance: u32, name: impl Into<String>) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::ESCALATOR, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            escalator_mode: EscalatorMode::UNKNOWN,
            fault_signals: Vec::new(),
            energy_meter: 0.0,
            energy_meter_ref: Vec::new(),
            power_mode: false,
            operation_direction: EscalatorOperationDirection::UNKNOWN,
            passenger_alarm: false,
            status_flags: StatusFlags::empty(),
            out_of_service: false,
            reliability: Reliability::NO_FAULT_DETECTED,
        })
    }
}

impl BACnetObject for EscalatorObject {
    fn object_identifier(&self) -> ObjectIdentifier {
        self.oid
    }

    fn object_name(&self) -> &str {
        &self.name
    }

    fn read_property(
        &self,
        property: PropertyIdentifier,
        array_index: Option<u32>,
    ) -> Result<PropertyValue, Error> {
        if let Some(result) = read_common_properties!(self, property, array_index) {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::OBJECT_TYPE => {
                Ok(PropertyValue::Enumerated(ObjectType::ESCALATOR.to_raw()))
            }
            p if p == PropertyIdentifier::ESCALATOR_MODE => {
                Ok(PropertyValue::Enumerated(self.escalator_mode.to_raw()))
            }
            p if p == PropertyIdentifier::FAULT_SIGNALS => {
                let items: Vec<PropertyValue> = self
                    .fault_signals
                    .iter()
                    .map(|v| PropertyValue::Enumerated(v.to_raw()))
                    .collect();
                Ok(PropertyValue::List(items))
            }
            p if p == PropertyIdentifier::ENERGY_METER => {
                Ok(PropertyValue::Real(self.energy_meter))
            }
            p if p == PropertyIdentifier::ENERGY_METER_REF => {
                Ok(PropertyValue::OctetString(self.energy_meter_ref.clone()))
            }
            p if p == PropertyIdentifier::POWER_MODE => Ok(PropertyValue::Boolean(self.power_mode)),
            p if p == PropertyIdentifier::OPERATION_DIRECTION => {
                Ok(PropertyValue::Enumerated(self.operation_direction.to_raw()))
            }
            p if p == PropertyIdentifier::PASSENGER_ALARM => {
                Ok(PropertyValue::Boolean(self.passenger_alarm))
            }
            _ => Err(common::unknown_property_error()),
        }
    }

    fn write_property(
        &mut self,
        property: PropertyIdentifier,
        _array_index: Option<u32>,
        value: PropertyValue,
        _priority: Option<u8>,
    ) -> Result<(), Error> {
        if let Some(result) =
            common::write_out_of_service(&mut self.out_of_service, property, &value)
        {
            return result;
        }
        if let Some(result) = common::write_description(&mut self.description, property, &value) {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::POWER_MODE => {
                if let PropertyValue::Boolean(v) = value {
                    self.power_mode = v;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            p if p == PropertyIdentifier::ESCALATOR_MODE => {
                if let PropertyValue::Enumerated(v) = value {
                    let mode = EscalatorMode::from_raw(v);
                    if !named_or_proprietary(EscalatorMode::ALL_NAMED, mode, v) {
                        return Err(common::value_out_of_range_error());
                    }
                    self.escalator_mode = mode;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            p if p == PropertyIdentifier::OPERATION_DIRECTION => {
                if let PropertyValue::Enumerated(v) = value {
                    // Validate before mutating so a refused write leaves the
                    // prior value intact.
                    let direction = EscalatorOperationDirection::from_raw(v);
                    if !named_or_proprietary(EscalatorOperationDirection::ALL_NAMED, direction, v) {
                        return Err(common::value_out_of_range_error());
                    }
                    self.operation_direction = direction;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            p if p == PropertyIdentifier::ENERGY_METER => {
                if let PropertyValue::Real(v) = value {
                    if !v.is_finite() {
                        return Err(common::value_out_of_range_error());
                    }
                    self.energy_meter = v;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            p if p == PropertyIdentifier::FAULT_SIGNALS => {
                let values = match value {
                    PropertyValue::Enumerated(v) => vec![PropertyValue::Enumerated(v)],
                    PropertyValue::List(values) => values,
                    _ => return Err(common::invalid_data_type_error()),
                };
                let mut faults = Vec::with_capacity(values.len());
                let mut seen = HashSet::with_capacity(values.len());
                for value in values {
                    let PropertyValue::Enumerated(raw) = value else {
                        return Err(common::invalid_data_type_error());
                    };
                    let fault = EscalatorFault::from_raw(raw);
                    if !named_or_proprietary(EscalatorFault::ALL_NAMED, fault, raw) {
                        return Err(common::value_out_of_range_error());
                    }
                    if !seen.insert(fault) {
                        return Err(common::value_out_of_range_error());
                    }
                    faults.push(fault);
                }
                self.fault_signals = faults;
                Ok(())
            }
            p if p == PropertyIdentifier::PASSENGER_ALARM => {
                if let PropertyValue::Boolean(v) = value {
                    self.passenger_alarm = v;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            _ => Err(crate::common::unhandled_write_error(
                self.property_metadata().as_ref(),
                property,
                _array_index,
            )),
        }
    }

    fn property_metadata(&self) -> Cow<'_, [crate::property_metadata::PropertyMetadata]> {
        metadata::for_escalator_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }
}

// ===========================================================================
// LiftObject (type 59)
// ===========================================================================

/// BACnet Lift object — represents a single lift/elevator car.
pub struct LiftObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    /// Tracking value (Unsigned — current floor).
    tracking_value: u64,
    /// Car position (Unsigned).
    car_position: u64,
    /// Car moving direction (BACnetLiftCarDirection, Clause 21); proprietary
    /// extensions (Clause 23.1) are preserved as raw values.
    car_moving_direction: LiftCarDirection,
    /// Car door status (List of Unsigned).
    car_door_status: Vec<u64>,
    /// Car load as a percentage (Unsigned).
    car_load: u64,
    /// Number of landing doors (stored as count).
    landing_doors: u64,
    /// Floor text labels (List of String).
    floor_text: Vec<String>,
    /// Energy meter reading (Real).
    energy_meter: f32,
    status_flags: StatusFlags,
    out_of_service: bool,
    reliability: Reliability,
}

impl LiftObject {
    /// Create a new Lift object with the given number of floors.
    ///
    /// Floor text is initialized to "Floor 1", "Floor 2", etc.
    pub fn new(instance: u32, name: impl Into<String>, num_floors: usize) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::LIFT, instance)?;
        let floor_text = (1..=num_floors).map(|i| format!("Floor {i}")).collect();
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            tracking_value: 1,
            car_position: 1,
            car_moving_direction: LiftCarDirection::STOPPED,
            car_door_status: Vec::new(),
            car_load: 0,
            landing_doors: num_floors as u64,
            floor_text,
            energy_meter: 0.0,
            status_flags: StatusFlags::empty(),
            out_of_service: false,
            reliability: Reliability::NO_FAULT_DETECTED,
        })
    }
}

impl BACnetObject for LiftObject {
    fn object_identifier(&self) -> ObjectIdentifier {
        self.oid
    }

    fn object_name(&self) -> &str {
        &self.name
    }

    fn read_property(
        &self,
        property: PropertyIdentifier,
        array_index: Option<u32>,
    ) -> Result<PropertyValue, Error> {
        if let Some(result) = read_common_properties!(self, property, array_index) {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::OBJECT_TYPE => {
                Ok(PropertyValue::Enumerated(ObjectType::LIFT.to_raw()))
            }
            p if p == PropertyIdentifier::TRACKING_VALUE => {
                Ok(PropertyValue::Unsigned(self.tracking_value))
            }
            p if p == PropertyIdentifier::CAR_POSITION => {
                Ok(PropertyValue::Unsigned(self.car_position))
            }
            p if p == PropertyIdentifier::CAR_MOVING_DIRECTION => Ok(PropertyValue::Enumerated(
                self.car_moving_direction.to_raw(),
            )),
            p if p == PropertyIdentifier::CAR_DOOR_STATUS => {
                let items: Vec<PropertyValue> = self
                    .car_door_status
                    .iter()
                    .map(|v| PropertyValue::Unsigned(*v))
                    .collect();
                Ok(PropertyValue::List(items))
            }
            p if p == PropertyIdentifier::CAR_LOAD => Ok(PropertyValue::Unsigned(self.car_load)),
            p if p == PropertyIdentifier::LANDING_DOOR_STATUS => {
                Ok(PropertyValue::Unsigned(self.landing_doors))
            }
            p if p == PropertyIdentifier::FLOOR_TEXT => {
                let items: Vec<PropertyValue> = self
                    .floor_text
                    .iter()
                    .map(|s| PropertyValue::CharacterString(s.clone()))
                    .collect();
                Ok(PropertyValue::List(items))
            }
            p if p == PropertyIdentifier::ENERGY_METER => {
                Ok(PropertyValue::Real(self.energy_meter))
            }
            p if p == PropertyIdentifier::FLOOR_NUMBER => {
                Ok(PropertyValue::Unsigned(self.tracking_value))
            }
            _ => Err(common::unknown_property_error()),
        }
    }

    fn write_property(
        &mut self,
        property: PropertyIdentifier,
        _array_index: Option<u32>,
        value: PropertyValue,
        _priority: Option<u8>,
    ) -> Result<(), Error> {
        if let Some(result) =
            common::write_out_of_service(&mut self.out_of_service, property, &value)
        {
            return result;
        }
        if let Some(result) = common::write_description(&mut self.description, property, &value) {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::TRACKING_VALUE => {
                if let PropertyValue::Unsigned(v) = value {
                    self.tracking_value = v;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            p if p == PropertyIdentifier::CAR_POSITION => {
                if let PropertyValue::Unsigned(v) = value {
                    self.car_position = v;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            p if p == PropertyIdentifier::CAR_MOVING_DIRECTION => {
                if let PropertyValue::Enumerated(v) = value {
                    let direction = LiftCarDirection::from_raw(v);
                    if !named_or_proprietary(LiftCarDirection::ALL_NAMED, direction, v) {
                        return Err(common::value_out_of_range_error());
                    }
                    self.car_moving_direction = direction;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            p if p == PropertyIdentifier::CAR_LOAD => {
                if let PropertyValue::Unsigned(v) = value {
                    if v > 100 {
                        return Err(common::value_out_of_range_error());
                    }
                    self.car_load = v;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            _ => Err(crate::common::unhandled_write_error(
                self.property_metadata().as_ref(),
                property,
                _array_index,
            )),
        }
    }

    fn property_metadata(&self) -> Cow<'_, [crate::property_metadata::PropertyMetadata]> {
        metadata::for_lift_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
