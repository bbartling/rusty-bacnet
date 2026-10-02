use super::*;

// AccessDoorObject (type 30)
// ---------------------------------------------------------------------------

/// BACnet Access Door object (type 30).
///
/// Represents a physical door or barrier in an access control system.
/// Present value carries the door command (BACnetDoorValue); Door_Status
/// reports the physical DoorStatus.
pub struct AccessDoorObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    present_value: DoorValue,
    door_status: DoorStatus,
    lock_status: LockStatus,
    secured_status: DoorSecuredStatus,
    door_alarm_state: DoorAlarmState,
    door_members: Vec<ObjectIdentifier>,
    status_flags: StatusFlags,
    /// Event_State.
    event_state: EventState,
    out_of_service: bool,
    reliability: Reliability,
    /// 16-level priority array for commandable Present_Value.
    priority_array: [Option<DoorValue>; 16],
    relinquish_default: DoorValue,
}

impl AccessDoorObject {
    /// Create a new Access Door object.
    pub fn new(instance: u32, name: impl Into<String>) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::ACCESS_DOOR, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            present_value: DoorValue::LOCK,
            door_status: DoorStatus::CLOSED,
            lock_status: LockStatus::LOCKED,
            secured_status: DoorSecuredStatus::SECURED,
            door_alarm_state: DoorAlarmState::NORMAL,
            door_members: Vec::new(),
            status_flags: StatusFlags::empty(),
            event_state: EventState::NORMAL,
            out_of_service: false,
            reliability: Reliability::NO_FAULT_DETECTED,
            priority_array: Default::default(),
            relinquish_default: DoorValue::LOCK,
        })
    }

    /// Set the Relinquish_Default (#270).
    ///
    /// Table 12-30 types both Present_Value and Relinquish_Default as
    /// BACnetDoorValue, whose Clause 21 production is a closed set of four
    /// (`DoorValue::LOCK..=DoorValue::EXTENDED_PULSE_UNLOCK`, 0..=3). A
    /// `DoorValue` made with `from_raw` can carry any number, so a value
    /// outside that set is refused with VALUE_OUT_OF_RANGE and the stored
    /// default is left unchanged; a commanded Present_Value is checked the
    /// same way (#979). After the store, Present_Value is resolved anew from
    /// the priority array so an empty array falls back to the new default
    /// immediately.
    pub fn set_relinquish_default(&mut self, value: DoorValue) -> Result<(), Error> {
        if !is_door_value(value) {
            return Err(common::value_out_of_range_error());
        }
        self.relinquish_default = value;
        self.recalculate_present_value();
        Ok(())
    }

    fn recalculate_present_value(&mut self) {
        self.present_value =
            common::recalculate_from_priority_array(&self.priority_array, self.relinquish_default);
    }
}

/// Whether `value` is one of the four BACnetDoorValue members. The
/// bacnet-types test `door_value_values_match_clause_21` pins the
/// production's closed-set length, so this bound cannot drift from the enum.
fn is_door_value(value: DoorValue) -> bool {
    value.to_raw() <= DoorValue::EXTENDED_PULSE_UNLOCK.to_raw()
}

/// Decode a BACnetDoorValue write: an Enumerated within the closed set.
fn checked_door_value(value: PropertyValue) -> Result<DoorValue, Error> {
    let PropertyValue::Enumerated(raw) = value else {
        return Err(common::invalid_data_type_error());
    };
    let value = DoorValue::from_raw(raw);
    if !is_door_value(value) {
        return Err(common::value_out_of_range_error());
    }
    Ok(value)
}

impl BACnetObject for AccessDoorObject {
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
                Ok(PropertyValue::Enumerated(ObjectType::ACCESS_DOOR.to_raw()))
            }
            p if p == PropertyIdentifier::PRESENT_VALUE => {
                Ok(PropertyValue::Enumerated(self.present_value.to_raw()))
            }
            p if p == PropertyIdentifier::DOOR_STATUS => {
                Ok(PropertyValue::Enumerated(self.door_status.to_raw()))
            }
            p if p == PropertyIdentifier::LOCK_STATUS => {
                Ok(PropertyValue::Enumerated(self.lock_status.to_raw()))
            }
            p if p == PropertyIdentifier::SECURED_STATUS => {
                Ok(PropertyValue::Enumerated(self.secured_status.to_raw()))
            }
            p if p == PropertyIdentifier::DOOR_ALARM_STATE => {
                Ok(PropertyValue::Enumerated(self.door_alarm_state.to_raw()))
            }
            p if p == PropertyIdentifier::DOOR_MEMBERS => Ok(PropertyValue::List(
                self.door_members
                    .iter()
                    .map(|oid| PropertyValue::ObjectIdentifier(*oid))
                    .collect(),
            )),
            p if p == PropertyIdentifier::EVENT_STATE => {
                Ok(PropertyValue::Enumerated(self.event_state.to_raw()))
            }
            p if p == PropertyIdentifier::PRIORITY_ARRAY => {
                common::read_priority_array!(self, array_index, |v: DoorValue| {
                    PropertyValue::Enumerated(v.to_raw())
                })
            }
            p if p == PropertyIdentifier::RELINQUISH_DEFAULT => {
                Ok(PropertyValue::Enumerated(self.relinquish_default.to_raw()))
            }
            _ => Err(common::unknown_property_error()),
        }
    }

    fn write_property(
        &mut self,
        property: PropertyIdentifier,
        _array_index: Option<u32>,
        value: PropertyValue,
        priority: Option<u8>,
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
            // A command (or a NULL relinquish) at the write priority, 16 when
            // absent; Present_Value is then resolved from the priority array.
            p if p == PropertyIdentifier::PRESENT_VALUE => {
                common::write_priority_array!(self, value, priority, checked_door_value)
            }
            // Table 12-30 carries Relinquish_Default R (BACnetDoorValue) for
            // the commandable Access Door; the standard permits writability.
            p if p == PropertyIdentifier::RELINQUISH_DEFAULT => {
                self.set_relinquish_default(checked_door_value(value)?)
            }
            _ => Err(crate::common::unhandled_write_error(
                self.property_metadata().as_ref(),
                property,
                _array_index,
            )),
        }
    }

    fn property_metadata(&self) -> Cow<'_, [crate::property_metadata::PropertyMetadata]> {
        super::metadata_topology::for_access_door_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }

    fn supports_cov(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
