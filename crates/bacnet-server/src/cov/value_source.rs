//! Table 13-1a-2 commandable Value_Source capture, shared by Single and Multiple.
use super::{flags::PreparedFlags, prepare::PreparedCovValue, CovObservation, CovSample};
use bacnet_encoding::{constructed::decode_value_source, primitives::decode_timestamp_choice};
use bacnet_objects::traits::BACnetObject;
use bacnet_services::common::BACnetPropertyValue;
use bacnet_types::{
    enums::{ObjectType as O, PropertyIdentifier as P},
    error::Error,
    primitives::PropertyValue as V,
};

const FIELDS: [P; 5] = [
    P::PRESENT_VALUE,
    P::STATUS_FLAGS,
    P::VALUE_SOURCE,
    P::LAST_COMMAND_TIME,
    P::CURRENT_COMMAND_PRIORITY,
];

pub(crate) fn applies(object: &dyn BACnetObject, property: P) -> bool {
    property == P::VALUE_SOURCE
        && matches!(
            object.object_identifier().object_type(),
            O::ANALOG_OUTPUT
                | O::ANALOG_VALUE
                | O::BINARY_OUTPUT
                | O::BINARY_VALUE
                | O::MULTI_STATE_OUTPUT
                | O::MULTI_STATE_VALUE
        )
        && object.property_list().contains(&P::PRIORITY_ARRAY)
}

/// Owns the complete validated report and baseline from one object borrow. Other
/// Multiple selectors reuse these captured values, never read a second version.
pub(crate) struct PreparedValueSource {
    fields: Vec<PreparedCovValue>,
    pub observation: CovObservation,
}
impl PreparedValueSource {
    pub fn read(object: &dyn BACnetObject, flags: &PreparedFlags) -> Result<Self, Error> {
        let mut fields = Vec::with_capacity(FIELDS.len());
        for property in FIELDS {
            let value = if property == P::STATUS_FLAGS {
                flags.value.clone().ok_or_else(invalid)?
            } else {
                object.read_property(property, None)?
            };
            // Bound before inspecting constructed payloads or retaining copies.
            CovSample::new(&value)?;
            validate(object.object_identifier().object_type(), property, &value)?;
            fields.push(super::prepare::prepare_value(
                object, property, None, None, &value,
            )?);
        }
        // Only analog PV uses the object's increment. A selected Value_Source
        // increment must never replace the object's Table 13-1 criterion.
        if !matches!(
            object.object_identifier().object_type(),
            O::ANALOG_OUTPUT | O::ANALOG_VALUE
        ) {
            fields[0].increment = None;
        }
        let observation = flags
            .observation(fields[2].sample.clone())
            .with_command(fields[0].sample.clone(), fields[4].sample.clone());
        Ok(Self {
            fields,
            observation,
        })
    }
    pub fn value(&self, property: P) -> Option<&V> {
        FIELDS
            .iter()
            .position(|p| *p == property)
            .map(|i| self.fields[i].sample.value())
    }
    pub fn reports(&self, previous: Option<&CovObservation>) -> bool {
        let Some(previous) = previous else {
            return true;
        };
        let Some((pv, priority)) = previous.command() else {
            return true;
        };
        self.fields[0].reports(Some(pv))
            || self.observation.flags_changed(Some(previous))
            || self.observation.sample() != previous.sample()
            || &self.fields[4].sample != priority
    }
    pub fn values(&self) -> Vec<BACnetPropertyValue> {
        FIELDS
            .into_iter()
            .zip(&self.fields)
            .map(|(property_identifier, field)| BACnetPropertyValue {
                property_identifier,
                property_array_index: None,
                value: field.encoded.clone(),
                priority: None,
            })
            .collect()
    }
}
fn invalid() -> Error {
    Error::Encoding("Invalid commandable Value_Source COV companion".into())
}
fn validate(object: O, property: P, value: &V) -> Result<(), Error> {
    let valid = match property {
        P::PRESENT_VALUE => match object {
            O::ANALOG_OUTPUT | O::ANALOG_VALUE => matches!(value, V::Real(v) if v.is_finite()),
            O::BINARY_OUTPUT | O::BINARY_VALUE => matches!(value, V::Enumerated(0..=1)),
            _ => matches!(value, V::Unsigned(1..=0xffff_ffff)),
        },
        P::VALUE_SOURCE => {
            matches!(value, V::ApplicationData(bytes) if decode_value_source(bytes, 0).is_ok_and(|(_, end)| end == bytes.len()))
        }
        P::LAST_COMMAND_TIME => {
            matches!(value, V::ApplicationData(bytes) if decode_timestamp_choice(bytes, 0).is_ok_and(|(_, end)| end == bytes.len()))
        }
        P::CURRENT_COMMAND_PRIORITY => matches!(value, V::Null | V::Unsigned(1..=16)),
        P::STATUS_FLAGS => super::observation::validate_flags(value).is_ok(),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(invalid())
    }
}
