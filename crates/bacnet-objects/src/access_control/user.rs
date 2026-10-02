use super::*;

// AccessUserObject (type 35)
// ---------------------------------------------------------------------------

/// BACnet Access User object (type 35).
///
/// Represents a person or entity that uses credentials to gain access. Its
/// kind lives in User_Type; Table 12-38 has no Present_Value,
/// Assigned_Access_Rights or Out_Of_Service row, so the object serves none of
/// them (#1064).
pub struct AccessUserObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    user_type: AccessUserType,
    credentials: Vec<ObjectIdentifier>,
    status_flags: StatusFlags,
    reliability: Reliability,
}

impl AccessUserObject {
    /// Create a new Access User object.
    pub fn new(instance: u32, name: impl Into<String>) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::ACCESS_USER, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            user_type: AccessUserType::ASSET,
            credentials: Vec::new(),
            status_flags: StatusFlags::empty(),
            reliability: Reliability::NO_FAULT_DETECTED,
        })
    }
}

impl BACnetObject for AccessUserObject {
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
        // Clause 12.33 holds the OUT_OF_SERVICE flag FALSE.
        if let Some(result) =
            read_common_properties!(self, property, array_index, no_out_of_service)
        {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::OBJECT_TYPE => {
                Ok(PropertyValue::Enumerated(ObjectType::ACCESS_USER.to_raw()))
            }
            p if p == PropertyIdentifier::USER_TYPE => {
                Ok(PropertyValue::Enumerated(self.user_type.to_raw()))
            }
            p if p == PropertyIdentifier::CREDENTIALS => Ok(PropertyValue::List(
                self.credentials
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
        _array_index: Option<u32>,
        value: PropertyValue,
        _priority: Option<u8>,
    ) -> Result<(), Error> {
        if let Some(result) = common::write_description(&mut self.description, property, &value) {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::USER_TYPE => {
                if let PropertyValue::Enumerated(v) = value {
                    self.user_type = AccessUserType::from_raw(v);
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
        super::metadata_identity::for_access_user_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }
}

// ---------------------------------------------------------------------------
