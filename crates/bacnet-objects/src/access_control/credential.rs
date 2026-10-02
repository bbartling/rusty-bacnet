use super::*;

// AccessCredentialObject (type 32)
// ---------------------------------------------------------------------------

/// BACnet Access Credential object (type 32).
///
/// Represents a credential (card, fob, biometric, etc.) used for access control.
/// Its active/inactive state lives in Credential_Status, a BACnetBinaryPV.
/// Table 12-40 has no Present_Value row, so the object serves none (#979).
pub struct AccessCredentialObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    credential_status: BinaryPV,
    assigned_access_rights_count: u32,
    authentication_factors: Vec<Vec<u8>>,
    status_flags: StatusFlags,
    reliability: Reliability,
}

impl AccessCredentialObject {
    /// Create a new Access Credential object.
    pub fn new(instance: u32, name: impl Into<String>) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::ACCESS_CREDENTIAL, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            credential_status: BinaryPV::INACTIVE,
            assigned_access_rights_count: 0,
            authentication_factors: Vec::new(),
            status_flags: StatusFlags::empty(),
            reliability: Reliability::NO_FAULT_DETECTED,
        })
    }
}

impl BACnetObject for AccessCredentialObject {
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
        // Table 12-40 has no Out_Of_Service (#1064), and Clause 12.35 holds the
        // OUT_OF_SERVICE flag FALSE.
        if let Some(result) =
            read_common_properties!(self, property, array_index, no_out_of_service)
        {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::OBJECT_TYPE => Ok(PropertyValue::Enumerated(
                ObjectType::ACCESS_CREDENTIAL.to_raw(),
            )),
            p if p == PropertyIdentifier::CREDENTIAL_STATUS => {
                Ok(PropertyValue::Enumerated(self.credential_status.to_raw()))
            }
            p if p == PropertyIdentifier::ASSIGNED_ACCESS_RIGHTS => Ok(PropertyValue::Unsigned(
                self.assigned_access_rights_count as u64,
            )),
            p if p == PropertyIdentifier::AUTHENTICATION_FACTORS => Ok(PropertyValue::List(
                self.authentication_factors
                    .iter()
                    .map(|f| PropertyValue::OctetString(f.clone()))
                    .collect(),
            )),
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
            // BACnetBinaryPV has two members, INACTIVE (0) and ACTIVE (1);
            // anything else is refused and the stored status kept.
            p if p == PropertyIdentifier::CREDENTIAL_STATUS => {
                let PropertyValue::Enumerated(raw) = value else {
                    return Err(common::invalid_data_type_error());
                };
                if raw > BinaryPV::ACTIVE.to_raw() {
                    return Err(common::value_out_of_range_error());
                }
                self.credential_status = BinaryPV::from_raw(raw);
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
        super::metadata_identity::for_access_credential_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }
}

// ---------------------------------------------------------------------------
