use bacnet_encoding::constructed::encode_authentication_factor;
use bacnet_types::constructed::BACnetAuthenticationFactor;
use bacnet_types::enums::AuthenticationFactorType;

use super::*;

// CredentialDataInputObject (type 37)
// ---------------------------------------------------------------------------

/// BACnet Credential Data Input object (type 37).
///
/// Represents a credential reader device (card reader, biometric scanner, etc.).
/// Its Present_Value is the last factor read, a `BACnetAuthenticationFactor`
/// (Clause 12.36.4), and Update_Time a `BACnetTimeStamp` (Clause 12.36.11);
/// both go out in their Clause 21 forms. The enumerated
/// BACnetAuthenticationStatus belongs to the Access Point's
/// Authentication_Status (Clause 12.31, Table 12-36), not here.
pub struct CredentialDataInputObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    present_value: BACnetAuthenticationFactor,
    update_time: BACnetTimeStamp,
    supported_formats: Vec<u64>,
    supported_format_classes: Vec<u64>,
    status_flags: StatusFlags,
    out_of_service: bool,
    reliability: Reliability,
}

impl CredentialDataInputObject {
    /// Create a new Credential Data Input object.
    ///
    /// Until the first read, Present_Value is the UNDEFINED factor (format
    /// class 0, no value octets) and Update_Time the unspecified date and
    /// time (Clauses 12.36.4 and 12.36.11).
    pub fn new(instance: u32, name: impl Into<String>) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::CREDENTIAL_DATA_INPUT, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            present_value: BACnetAuthenticationFactor {
                format_type: AuthenticationFactorType::UNDEFINED,
                format_class: 0,
                value: Vec::new(),
            },
            update_time: never_updated(),
            supported_formats: Vec::new(),
            supported_format_classes: Vec::new(),
            status_flags: StatusFlags::empty(),
            out_of_service: false,
            reliability: Reliability::NO_FAULT_DETECTED,
        })
    }

    /// Record a factor the reader has read: Present_Value takes `factor` and
    /// Update_Time `update_time`, together, since Clause 12.36.11 moves
    /// Update_Time on every Present_Value update. Reading the same factor
    /// again is such an update.
    ///
    /// A change of Update_Time triggers a SubscribeCOV notification
    /// (Table 13-1). Over the network both properties stay read-only.
    pub fn set_present_value(
        &mut self,
        factor: BACnetAuthenticationFactor,
        update_time: BACnetTimeStamp,
    ) {
        self.present_value = factor;
        self.update_time = update_time;
    }
}

impl BACnetObject for CredentialDataInputObject {
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
            p if p == PropertyIdentifier::OBJECT_TYPE => Ok(PropertyValue::Enumerated(
                ObjectType::CREDENTIAL_DATA_INPUT.to_raw(),
            )),
            p if p == PropertyIdentifier::PRESENT_VALUE => {
                let mut buf = BytesMut::new();
                encode_authentication_factor(&mut buf, &self.present_value);
                Ok(PropertyValue::ApplicationData(buf.to_vec()))
            }
            p if p == PropertyIdentifier::UPDATE_TIME => timestamp_value(&self.update_time),
            p if p == PropertyIdentifier::SUPPORTED_FORMATS => Ok(PropertyValue::List(
                self.supported_formats
                    .iter()
                    .map(|v| PropertyValue::Unsigned(*v))
                    .collect(),
            )),
            p if p == PropertyIdentifier::SUPPORTED_FORMAT_CLASSES => Ok(PropertyValue::List(
                self.supported_format_classes
                    .iter()
                    .map(|v| PropertyValue::Unsigned(*v))
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
        if let Some(result) =
            common::write_out_of_service(&mut self.out_of_service, property, &value)
        {
            return result;
        }
        if let Some(result) = common::write_description(&mut self.description, property, &value) {
            return result;
        }
        // CredentialDataInput is primarily read-only (driven by hardware)
        Err(crate::common::unhandled_write_error(
            self.property_metadata().as_ref(),
            property,
            _array_index,
        ))
    }

    fn property_metadata(&self) -> Cow<'_, [crate::property_metadata::PropertyMetadata]> {
        super::metadata_identity::for_credential_data_input_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }

    /// Table 13-1 lists Credential Data Input, so it takes SubscribeCOV.
    fn supports_cov(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
