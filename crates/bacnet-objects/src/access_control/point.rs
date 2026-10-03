use super::*;

// AccessPointObject (type 33)
// ---------------------------------------------------------------------------

/// BACnet Access Point object (type 33).
///
/// Represents an access point (reader/controller at a door) in an access control system.
/// The most recent access event is Access_Event; Table 12-36 has no
/// Present_Value row, so the object serves none (#1064).
pub struct AccessPointObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    access_event: AccessEvent,
    access_event_tag: u64,
    access_event_time: BACnetTimeStamp,
    access_doors: Vec<BACnetDeviceObjectReference>,
    event_state: EventState,
    status_flags: StatusFlags,
    out_of_service: bool,
    reliability: Reliability,
}

impl AccessPointObject {
    /// Create a new Access Point object.
    pub fn new(instance: u32, name: impl Into<String>) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::ACCESS_POINT, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            access_event: AccessEvent::NONE,
            access_event_tag: 0,
            access_event_time: never_updated(),
            access_doors: Vec::new(),
            event_state: EventState::NORMAL,
            status_flags: StatusFlags::empty(),
            out_of_service: false,
            reliability: Reliability::NO_FAULT_DETECTED,
        })
    }

    /// Record the most recent access event: Access_Event, Access_Event_Tag
    /// and Access_Event_Time, which the application's access logic produces.
    ///
    /// Access_Event_Time is a `BACnetTimeStamp` (Clause 12.31.29) and goes
    /// out in its Clause 21 CHOICE form. A change of it triggers a SubscribeCOV
    /// notification; the event and its tag only ride along (Table 13-1). Over
    /// the network all three stay read-only.
    pub fn set_access_event(&mut self, event: AccessEvent, tag: u64, time: BACnetTimeStamp) {
        self.access_event = event;
        self.access_event_tag = tag;
        self.access_event_time = time;
    }

    /// Set Access_Doors, the Access Door objects whose Present_Value this
    /// point commands once access is granted (Clause 12.31.32). A point that
    /// commands no door keeps the array empty. A reference with no Device
    /// identifier names an object in this device.
    ///
    /// Every reference must name an Access Door object; a list holding any
    /// other object type is refused with VALUE_OUT_OF_RANGE and the doors set
    /// before are kept. The array is read-only over the network.
    pub fn set_access_doors(
        &mut self,
        doors: impl IntoIterator<Item = impl Into<BACnetDeviceObjectReference>>,
    ) -> Result<(), Error> {
        let doors: Vec<BACnetDeviceObjectReference> = doors.into_iter().map(Into::into).collect();
        if doors
            .iter()
            .any(|door| door.object_identifier.object_type() != ObjectType::ACCESS_DOOR)
        {
            return Err(common::value_out_of_range_error());
        }
        self.access_doors = doors;
        Ok(())
    }
}

impl BACnetObject for AccessPointObject {
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
                Ok(PropertyValue::Enumerated(ObjectType::ACCESS_POINT.to_raw()))
            }
            p if p == PropertyIdentifier::ACCESS_EVENT => {
                Ok(PropertyValue::Enumerated(self.access_event.to_raw()))
            }
            p if p == PropertyIdentifier::ACCESS_EVENT_TAG => {
                Ok(PropertyValue::Unsigned(self.access_event_tag))
            }
            p if p == PropertyIdentifier::ACCESS_EVENT_TIME => {
                timestamp_value(&self.access_event_time)
            }
            p if p == PropertyIdentifier::ACCESS_DOORS => {
                common::read_array(device_object_references(&self.access_doors), array_index)
            }
            p if p == PropertyIdentifier::EVENT_STATE => {
                Ok(PropertyValue::Enumerated(self.event_state.to_raw()))
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
        Err(crate::common::unhandled_write_error(
            self.property_metadata().as_ref(),
            property,
            _array_index,
        ))
    }

    fn property_metadata(&self) -> Cow<'_, [crate::property_metadata::PropertyMetadata]> {
        super::metadata_topology::for_access_point_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }

    /// Table 13-1 lists Access Point, so it takes SubscribeCOV; its report
    /// leads with Access_Event, as the point has no Present_Value.
    fn supports_cov(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
