//! Judging a Pulse Converter's Input_Reference against the database (Clause
//! 12.23.9, #1341).
//!
//! The object can't see the object its reference names, so the database
//! looks: the reference is usable when it names another object here, at a
//! property that reads as an Unsigned or an INTEGER (an index only on an
//! array). Anything else, a missing object or property included, is a
//! CONFIGURATION_ERROR. A Pulse Converter's own properties are no input to
//! it. An unset reference is no fault.
//!
//! The verdict is taken when the reference is written (the server calls
//! [`ObjectDatabase::check_input_reference`] as the write commits), when the
//! Pulse Converter is added, and whenever an object a reference names is
//! added, replaced or removed (`ObjectDatabase::add` and `remove`). A change
//! inside the named object that alters its property's datatype is not
//! watched; the next of those events judges it again.
//!
//! [`ObjectDatabase::count_pulse_inputs`] reads the same property for the
//! count itself (Clause 12.23.14), with the same rule for what is readable.

use bacnet_types::constructed::BACnetObjectPropertyReference;
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};

use super::ObjectDatabase;

impl ObjectDatabase {
    /// Judge the Input_Reference of the Pulse Converter `oid` against this
    /// database and hand it the verdict; returns whether its Reliability
    /// changed, so the caller owes COV for it. Any other object, or one this
    /// database doesn't hold, is left alone.
    ///
    /// The bundled server calls this as a write of Input_Reference commits,
    /// over WriteProperty, WritePropertyMultiple, CreateObject or the local
    /// write path; adding and removing objects calls it for the converters
    /// concerned.
    pub fn check_input_reference(&mut self, oid: &ObjectIdentifier) -> bool {
        let Some(usable) = self.objects.get(oid).and_then(|object| {
            let reference = object.input_reference_internal()?;
            Some(reference.is_none_or(|reference| self.input_reading(*oid, reference).is_some()))
        }) else {
            return false;
        };
        self.objects
            .get_mut(oid)
            .is_some_and(|object| object.set_input_usable_internal(usable))
    }

    /// Judge again every Pulse Converter whose Input_Reference names
    /// `changed`, and `changed` itself when it is one, after it was added,
    /// replaced or removed; returns those whose Reliability changed.
    pub(super) fn recheck_input_references(
        &mut self,
        changed: ObjectIdentifier,
    ) -> Vec<ObjectIdentifier> {
        let concerned: Vec<_> = self
            .type_index
            .get(&ObjectType::PULSE_CONVERTER)
            .into_iter()
            .flatten()
            .copied()
            .filter(|converter| {
                *converter == changed
                    || self
                        .objects
                        .get(converter)
                        .and_then(|object| object.input_reference_internal().flatten())
                        .is_some_and(|reference| reference.object_identifier == changed)
            })
            .collect();
        concerned
            .into_iter()
            .filter(|converter| self.check_input_reference(converter))
            .collect()
    }

    /// Read the property each Pulse Converter's Input_Reference names and
    /// hand the reading over, so the converter counts its increase into
    /// Count (Clause 12.23.14); returns the converters whose Count changed,
    /// for COV. A converter with nothing readable to count from gets `None`,
    /// which drops its baseline.
    ///
    /// The bundled server runs this once a second. Reads go through
    /// [`BACnetObject::read_property`](crate::traits::BACnetObject::read_property),
    /// so they must stay bounded, as for Averaging sampling.
    pub fn count_pulse_inputs(&mut self) -> Vec<ObjectIdentifier> {
        let converters = self.find_by_type(ObjectType::PULSE_CONVERTER);
        let mut counted = Vec::new();
        for oid in converters {
            let reading = self.objects.get(&oid).and_then(|object| {
                let reference = object.input_reference_internal()??;
                self.input_reading(oid, reference)
            });
            if self
                .objects
                .get_mut(&oid)
                .is_some_and(|object| object.take_input_reading_internal(reading))
            {
                counted.push(oid);
            }
        }
        counted
    }

    /// What the converter `converter` reads from `reference`: the value of
    /// the named property of another object in this database, when it is an
    /// Unsigned or an INTEGER. An index goes only on an array, as
    /// ReadProperty's gate has it; anything else, a read error included, is
    /// `None`, an input the converter can't count from.
    fn input_reading(
        &self,
        converter: ObjectIdentifier,
        reference: &BACnetObjectPropertyReference,
    ) -> Option<i128> {
        if reference.object_identifier == converter {
            return None;
        }
        let target = self.get(&reference.object_identifier)?;
        let property = PropertyIdentifier::from_raw(reference.property_identifier);
        let index = reference.property_array_index;
        if index.is_some() && !target.is_array_property(property) {
            return None;
        }
        match target.read_property(property, index) {
            Ok(PropertyValue::Unsigned(value)) => Some(i128::from(value)),
            Ok(PropertyValue::Signed(value)) => Some(i128::from(value)),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "input_references_tests.rs"]
mod tests;
