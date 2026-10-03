use super::zone_out_of_service::ZoneState;
use super::*;

// AccessZoneObject (type 36)
// ---------------------------------------------------------------------------

/// BACnet Access Zone object (type 36).
///
/// Represents a physical zone or area controlled by access points. Table
/// 12-37 has neither Present_Value nor Access_Doors, so the object serves
/// neither (#1064).
///
/// While Out_Of_Service is TRUE a client can simulate Occupancy_Count and
/// Reliability by writing them, and the zone's own values come back on the
/// return to service (Table 12-37 footnote 1; #1247). The module
/// `zone_out_of_service` has the details.
pub struct AccessZoneObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    global_identifier: u64,
    /// Occupancy_Count and Reliability as served: the zone's own, or a
    /// client's simulation while Out_Of_Service is TRUE.
    state: ZoneState,
    /// The zone's own values, put aside while Out_Of_Service is TRUE.
    device_state: Option<ZoneState>,
    entry_points: Vec<ObjectIdentifier>,
    exit_points: Vec<ObjectIdentifier>,
    out_of_service: bool,
}

impl AccessZoneObject {
    /// Create a new Access Zone object.
    pub fn new(instance: u32, name: impl Into<String>) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::ACCESS_ZONE, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            global_identifier: 0,
            state: ZoneState {
                occupancy_count: 0,
                reliability: Reliability::NO_FAULT_DETECTED,
            },
            device_state: None,
            entry_points: Vec::new(),
            exit_points: Vec::new(),
            out_of_service: false,
        })
    }

    /// Record the zone's occupancy count, as the application's counting
    /// works it out (Clause 12.32.11). Over the network Occupancy_Count takes
    /// writes only while Out_Of_Service is TRUE; meanwhile the client's
    /// simulated count keeps being served, and this one takes over on the
    /// return to service.
    pub fn set_occupancy_count(&mut self, count: u64) {
        self.device_state_mut().occupancy_count = count;
    }

    /// The zone's own values: the ones put aside while out of service, else
    /// the ones served.
    fn device_state_mut(&mut self) -> &mut ZoneState {
        self.device_state.as_mut().unwrap_or(&mut self.state)
    }
}

impl BACnetObject for AccessZoneObject {
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
        if let Some(result) = crate::common::read_identity_properties!(self, property, array_index)
        {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::OBJECT_TYPE => {
                Ok(PropertyValue::Enumerated(ObjectType::ACCESS_ZONE.to_raw()))
            }
            // OVERRIDDEN stays clear (Clause 12.32.7), and the zone runs no
            // intrinsic reporting, so IN_ALARM does too.
            p if p == PropertyIdentifier::STATUS_FLAGS => Ok(common::compute_status_flags(
                StatusFlags::empty(),
                self.state.reliability,
                self.out_of_service,
                EventState::NORMAL,
            )),
            p if p == PropertyIdentifier::OUT_OF_SERVICE => {
                Ok(PropertyValue::Boolean(self.out_of_service))
            }
            p if p == PropertyIdentifier::RELIABILITY => {
                Ok(PropertyValue::Enumerated(self.state.reliability.to_raw()))
            }
            p if p == PropertyIdentifier::GLOBAL_IDENTIFIER => {
                Ok(PropertyValue::Unsigned(self.global_identifier))
            }
            p if p == PropertyIdentifier::OCCUPANCY_COUNT => {
                Ok(PropertyValue::Unsigned(self.state.occupancy_count))
            }
            p if p == PropertyIdentifier::ENTRY_POINTS => Ok(PropertyValue::List(
                self.entry_points
                    .iter()
                    .map(|oid| PropertyValue::ObjectIdentifier(*oid))
                    .collect(),
            )),
            p if p == PropertyIdentifier::EXIT_POINTS => Ok(PropertyValue::List(
                self.exit_points
                    .iter()
                    .map(|oid| PropertyValue::ObjectIdentifier(*oid))
                    .collect(),
            )),
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
        // The zone starts in service and only this write moves Out_Of_Service,
        // so the entry edge is always seen and there is no fallback.
        if let Some(result) = common::write_out_of_service_with_restore(
            &mut self.out_of_service,
            &mut self.state,
            &mut self.device_state,
            None,
            property,
            &value,
        ) {
            return result;
        }
        if let Some(result) = common::write_description(&mut self.description, property, &value) {
            return result;
        }
        if let Some(result) = self.state.write(self.out_of_service, property, &value) {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::GLOBAL_IDENTIFIER => {
                if let PropertyValue::Unsigned(v) = value {
                    self.global_identifier = v;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            _ => Err(common::unhandled_write_error(
                self.property_metadata().as_ref(),
                property,
                array_index,
            )),
        }
    }

    fn property_metadata(&self) -> Cow<'_, [crate::property_metadata::PropertyMetadata]> {
        super::metadata_topology::for_access_zone_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }

    /// The Reliability the zone's fault detection works out. Like the other
    /// Reliability carriers, the zone refuses it with WRITE_ACCESS_DENIED
    /// while Out_Of_Service is TRUE, so a client's simulated value stays
    /// served; the return to service brings back the value from before. A
    /// value outside the BACnetReliability production is refused with
    /// VALUE_OUT_OF_RANGE.
    fn set_reliability_internal(&mut self, reliability: Reliability) -> Result<(), Error> {
        if self.out_of_service {
            return Err(common::write_access_denied_error());
        }
        self.state.reliability = checked_reliability(reliability)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
