//! The Lift object (type 59, Clause 12.59).

use bacnet_encoding::constructed::encode_landing_door_status;
use bacnet_types::constructed::{BACnetDeviceObjectReference, BACnetLandingDoorStatus};
use bacnet_types::enums::{
    DoorStatus, EngineeringUnits, LiftCarDirection, LiftFault, ObjectType, PropertyIdentifier,
    Reliability,
};
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue, StatusFlags};
use bytes::BytesMut;
use std::borrow::Cow;

use super::doors;
use super::energy_meter::{energy_meter_accessors, EnergyMeter};
use super::membership::{group_membership_accessors, GroupMembership};
use super::{decode_fault_signals, metadata, named_or_proprietary};
use crate::common::{self, read_common_properties};
use crate::traits::BACnetObject;

/// BACnet Lift object — represents a single lift/elevator car.
///
/// The object serves the rows of its table (Clause 12.59, Table 12-77) that
/// it implements, each with its table datatype. Car_Door_Status and
/// Landing_Door_Status hold one element per car door and always have the
/// same size, as Clause 12.59 requires of the per-door arrays. Both take
/// WriteProperty only while Out_Of_Service is TRUE.
pub struct LiftObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    /// Elevator_Group, Group_ID and Installation_ID.
    membership: GroupMembership,
    /// Floor_Text: one label per universal floor number, floor 1 first.
    floor_text: Vec<String>,
    /// Car_Position: the universal floor number of the car (Unsigned8).
    car_position: u8,
    /// Car moving direction (BACnetLiftCarDirection, Clause 21); proprietary
    /// extensions (Clause 23.1) are preserved as raw values.
    pub(super) car_moving_direction: LiftCarDirection,
    /// Car_Door_Status: the status of each car door (BACnetDoorStatus).
    car_door_status: Vec<DoorStatus>,
    /// Car_Load (REAL), in `car_load_units`.
    car_load: f32,
    /// Car_Load_Units, present because Car_Load is.
    car_load_units: EngineeringUnits,
    /// Passenger alarm state (Boolean).
    passenger_alarm: bool,
    /// Energy_Meter and Energy_Meter_Ref.
    energy_meter: EnergyMeter,
    status_flags: StatusFlags,
    out_of_service: bool,
    reliability: Reliability,
    /// Fault signal set (BACnetLiftFault, Clause 21).
    fault_signals: Vec<LiftFault>,
    /// Landing_Door_Status: for each car door, the landing doors it pairs
    /// with.
    landing_door_status: Vec<BACnetLandingDoorStatus>,
}

impl LiftObject {
    /// Create a new Lift object with the given number of floors.
    ///
    /// Floor text is initialized to "Floor 1", "Floor 2", etc. The car has
    /// one door, whose status is UNKNOWN and which reports no landing doors,
    /// and Car_Load is 0.0 percent.
    pub fn new(instance: u32, name: impl Into<String>, num_floors: usize) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::LIFT, instance)?;
        let floor_text = (1..=num_floors).map(|i| format!("Floor {i}")).collect();
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            membership: GroupMembership::new()?,
            floor_text,
            car_position: 1,
            car_moving_direction: LiftCarDirection::STOPPED,
            car_door_status: vec![DoorStatus::UNKNOWN],
            car_load: 0.0,
            car_load_units: EngineeringUnits::PERCENT,
            passenger_alarm: false,
            energy_meter: EnergyMeter::new()?,
            status_flags: StatusFlags::empty(),
            out_of_service: false,
            reliability: Reliability::NO_FAULT_DETECTED,
            fault_signals: Vec::new(),
            landing_door_status: vec![BACnetLandingDoorStatus::default()],
        })
    }

    group_membership_accessors!("lift");
    energy_meter_accessors!("lift");

    /// The status of each car door, served as Car_Door_Status.
    pub fn car_door_status(&self) -> &[DoorStatus] {
        &self.car_door_status
    }

    /// Set the status of each car door, one element per door.
    ///
    /// Its size is the number of car doors, so a list of a different size
    /// changes that number, and Landing_Door_Status follows: a removed door's
    /// landing doors are dropped and an added door starts with none. A
    /// WriteProperty, accepted only while Out_Of_Service is TRUE, can't
    /// change the size, so this is the only way to. A status outside
    /// BACnetDoorStatus (a reserved value, or one above 65535) is refused
    /// with VALUE_OUT_OF_RANGE and both properties are left unchanged.
    pub fn set_car_door_status(&mut self, status: Vec<DoorStatus>) -> Result<(), Error> {
        if !status.iter().all(|&door| doors::door_status_in_range(door)) {
            return Err(common::value_out_of_range_error());
        }
        self.landing_door_status
            .resize_with(status.len(), BACnetLandingDoorStatus::default);
        self.car_door_status = status;
        Ok(())
    }

    /// The landing doors of each car door, served as Landing_Door_Status.
    pub fn landing_door_status(&self) -> &[BACnetLandingDoorStatus] {
        &self.landing_door_status
    }

    /// Set the landing doors of each car door, one element per car door.
    ///
    /// A list whose size differs from Car_Door_Status, or a landing door
    /// status outside BACnetDoorStatus, is refused with VALUE_OUT_OF_RANGE
    /// and the property is left unchanged. A WriteProperty, accepted only
    /// while Out_Of_Service is TRUE, follows the same rules.
    pub fn set_landing_door_status(
        &mut self,
        status: Vec<BACnetLandingDoorStatus>,
    ) -> Result<(), Error> {
        let in_range = status.iter().all(doors::landing_doors_in_range);
        if status.len() != self.car_door_status.len() || !in_range {
            return Err(common::value_out_of_range_error());
        }
        self.landing_door_status = status;
        Ok(())
    }

    /// The units of Car_Load, served as Car_Load_Units.
    pub fn car_load_units(&self) -> EngineeringUnits {
        self.car_load_units
    }

    /// Set the units Car_Load is measured in. A new Lift uses PERCENT.
    ///
    /// Car_Load_Units is read-only over the network. A value above 65535,
    /// outside BACnetEngineeringUnits, is refused with VALUE_OUT_OF_RANGE and
    /// the property is left unchanged.
    pub fn set_car_load_units(&mut self, units: EngineeringUnits) -> Result<(), Error> {
        if units.to_raw() > 65_535 {
            return Err(common::value_out_of_range_error());
        }
        self.car_load_units = units;
        Ok(())
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
        if let Some(value) = self.membership.read(property) {
            return Ok(value);
        }
        if let Some(value) = self.energy_meter.read(property) {
            return Ok(value);
        }
        match property {
            p if p == PropertyIdentifier::OBJECT_TYPE => {
                Ok(PropertyValue::Enumerated(ObjectType::LIFT.to_raw()))
            }
            p if p == PropertyIdentifier::FLOOR_TEXT => common::read_array(
                self.floor_text
                    .iter()
                    .cloned()
                    .map(PropertyValue::CharacterString)
                    .collect(),
                array_index,
            ),
            p if p == PropertyIdentifier::CAR_POSITION => {
                Ok(PropertyValue::Unsigned(self.car_position.into()))
            }
            p if p == PropertyIdentifier::CAR_MOVING_DIRECTION => Ok(PropertyValue::Enumerated(
                self.car_moving_direction.to_raw(),
            )),
            p if p == PropertyIdentifier::CAR_DOOR_STATUS => common::read_array(
                self.car_door_status
                    .iter()
                    .map(|door| PropertyValue::Enumerated(door.to_raw()))
                    .collect(),
                array_index,
            ),
            p if p == PropertyIdentifier::CAR_LOAD => Ok(PropertyValue::Real(self.car_load)),
            p if p == PropertyIdentifier::CAR_LOAD_UNITS => {
                Ok(PropertyValue::Enumerated(self.car_load_units.to_raw()))
            }
            p if p == PropertyIdentifier::PASSENGER_ALARM => {
                Ok(PropertyValue::Boolean(self.passenger_alarm))
            }
            p if p == PropertyIdentifier::FAULT_SIGNALS => Ok(PropertyValue::List(
                self.fault_signals
                    .iter()
                    .map(|fault| PropertyValue::Enumerated(fault.to_raw()))
                    .collect(),
            )),
            p if p == PropertyIdentifier::LANDING_DOOR_STATUS => common::read_array(
                self.landing_door_status
                    .iter()
                    .map(|car_door| {
                        let mut encoded = BytesMut::new();
                        encode_landing_door_status(&mut encoded, car_door);
                        PropertyValue::ApplicationData(encoded.to_vec())
                    })
                    .collect(),
                array_index,
            ),
            _ => Err(common::unknown_property_error()),
        }
    }

    fn write_property(
        &mut self,
        property: PropertyIdentifier,
        array_index: Option<u32>,
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
        if let Some(result) = self.energy_meter.write(property, &value) {
            return result;
        }
        match property {
            // Simulation writes (item (c) of the Out_Of_Service description).
            // Neither can change the car door count, so the two arrays keep
            // the same size.
            p if p == PropertyIdentifier::CAR_DOOR_STATUS => {
                if !self.out_of_service {
                    return Err(common::write_access_denied_error());
                }
                self.car_door_status = doors::written_array(
                    &self.car_door_status,
                    array_index,
                    value,
                    doors::decode_car_door,
                )?;
                Ok(())
            }
            p if p == PropertyIdentifier::LANDING_DOOR_STATUS => {
                if !self.out_of_service {
                    return Err(common::write_access_denied_error());
                }
                self.landing_door_status = doors::written_array(
                    &self.landing_door_status,
                    array_index,
                    value,
                    doors::decode_landing_doors,
                )?;
                Ok(())
            }
            p if p == PropertyIdentifier::CAR_POSITION => {
                if let PropertyValue::Unsigned(v) = value {
                    // Car_Position is an Unsigned8 (Table 12-77).
                    self.car_position =
                        u8::try_from(v).map_err(|_| common::value_out_of_range_error())?;
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
                if let PropertyValue::Real(v) = value {
                    common::reject_non_finite(v)?;
                    self.car_load = v;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            p if p == PropertyIdentifier::PASSENGER_ALARM => {
                if let PropertyValue::Boolean(v) = value {
                    self.passenger_alarm = v;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            p if p == PropertyIdentifier::FAULT_SIGNALS => {
                self.fault_signals =
                    decode_fault_signals(value, LiftFault::ALL_NAMED, LiftFault::from_raw)?;
                Ok(())
            }
            _ => Err(crate::common::unhandled_write_error(
                self.property_metadata().as_ref(),
                property,
                array_index,
            )),
        }
    }

    fn is_array_property(&self, property: PropertyIdentifier) -> bool {
        // The BACnetARRAY rows of Table 12-77 that the object serves.
        matches!(
            property,
            PropertyIdentifier::PROPERTY_LIST
                | PropertyIdentifier::FLOOR_TEXT
                | PropertyIdentifier::CAR_DOOR_STATUS
                | PropertyIdentifier::LANDING_DOOR_STATUS
        )
    }

    fn property_metadata(&self) -> Cow<'_, [crate::property_metadata::PropertyMetadata]> {
        metadata::for_lift_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }
}
