//! Table 13-1 values an ordinary (SubscribeCOV) notification reports after
//! Present_Value and Status_Flags, captured under the same object borrow.
use super::CovSample;
use bacnet_encoding::primitives::encode_property_value;
use bacnet_objects::traits::BACnetObject;
use bacnet_services::common::BACnetPropertyValue;
use bacnet_types::error::Error;
use bytes::BytesMut;

/// The encoded extra values in report order, and the bounded samples of those
/// whose changes trigger a notification. A declared property the object's
/// Property_List lacks is left out; a listed one that fails to read fails the
/// whole capture, as an unreadable Present_Value does.
pub(crate) struct PreparedReported {
    pub values: Vec<BACnetPropertyValue>,
    pub triggers: Box<[CovSample]>,
}
impl PreparedReported {
    pub fn read(object: &dyn BACnetObject) -> Result<Self, Error> {
        let declared = object.cov_reported_properties();
        if declared.is_empty() {
            return Ok(Self {
                values: Vec::new(),
                triggers: Box::default(),
            });
        }
        let property_list = object.property_list();
        let mut values = Vec::with_capacity(declared.len());
        let mut triggers = Vec::new();
        for reported in declared {
            let property = reported.property();
            if !property_list.contains(&property) {
                continue;
            }
            let value = object.read_property(property, None)?;
            // Bound before encoding or retaining a copy.
            let sample = CovSample::new(&value)?;
            let mut encoded = BytesMut::new();
            encode_property_value(&mut encoded, sample.value())?;
            values.push(BACnetPropertyValue {
                property_identifier: property,
                property_array_index: None,
                value: encoded.to_vec(),
                priority: None,
            });
            if reported.triggers() {
                triggers.push(sample);
            }
        }
        Ok(Self {
            values,
            triggers: triggers.into_boxed_slice(),
        })
    }
}
