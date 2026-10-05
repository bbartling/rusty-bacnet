//! Following an Event_Algorithm_Inhibit_Ref (#1329).
//!
//! An intrinsic reporter can't see the object its reference names, so the
//! database reads the property for it. The reference is a
//! BACnetObjectPropertyReference, which has no device member, so it only
//! ever names a property of this device; there is nothing remote to read.
//! The clauses that define the pair (Clause 12.2.31 and its counterparts)
//! map a BinaryPV of ACTIVE to TRUE and INACTIVE to FALSE, and take a
//! property that doesn't exist as FALSE. This device also takes FALSE from
//! a property it can't read or that holds another datatype.
//!
//! The bundled server follows the reference every time it evaluates the
//! object: the evaluation a write of the object runs, and the one-second
//! tick every intrinsic reporter gets. A change to the referenced property
//! therefore reaches Event_Algorithm_Inhibit, and the algorithm, within a
//! second, and a read of Event_Algorithm_Inhibit returns the value as of
//! the last evaluation. Both reads happen under the database guard the
//! evaluation already holds, so following takes no lock of its own.

use bacnet_types::constructed::BACnetObjectPropertyReference;
use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};

use super::ObjectDatabase;

impl ObjectDatabase {
    /// Read the property the object `oid`'s Event_Algorithm_Inhibit_Ref
    /// names and hand the value over as its Event_Algorithm_Inhibit; returns
    /// whether that changed. An object with no reference, one that doesn't
    /// report intrinsically, or one this database doesn't hold is left
    /// alone.
    pub fn follow_event_algorithm_inhibit(&mut self, oid: &ObjectIdentifier) -> bool {
        let Some(reference) = self
            .objects
            .get(oid)
            .and_then(|object| object.event_algorithm_inhibit_reference_internal())
        else {
            return false;
        };
        let inhibit = self.inhibit_value(&reference);
        self.objects
            .get_mut(oid)
            .is_some_and(|object| object.follow_event_algorithm_inhibit_internal(inhibit))
    }

    /// The Boolean the referenced property stands for; see the module
    /// documentation.
    fn inhibit_value(&self, reference: &BACnetObjectPropertyReference) -> bool {
        let property = PropertyIdentifier::from_raw(reference.property_identifier);
        let value = self.get(&reference.object_identifier).and_then(|object| {
            object
                .read_property(property, reference.property_array_index)
                .ok()
        });
        matches!(
            value,
            Some(PropertyValue::Boolean(true) | PropertyValue::Enumerated(1))
        )
    }
}

#[cfg(test)]
#[path = "event_algorithm_inhibit_tests.rs"]
mod tests;
