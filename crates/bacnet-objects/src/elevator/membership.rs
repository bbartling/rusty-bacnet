//! Elevator_Group, Group_ID and Installation_ID, the three required rows that
//! the Lift (Clause 12.59, Table 12-77) and Escalator (Clause 12.60,
//! Table 12-78) tables share: which Elevator Group the installation belongs
//! to, and the identification numbers of its group and of the installation
//! itself.
//!
//! Both tables give all three the R code, and they describe how the
//! installation is put together, which the application owns. So they are
//! read-only over the network: a WriteProperty on any of them is refused with
//! WRITE_ACCESS_DENIED, and the application sets them through the setters
//! [`group_membership_accessors`] adds to each object.

use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};

use crate::common;

/// The group placement of one lift or escalator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct GroupMembership {
    /// The Elevator Group that counts this object among its Group_Members.
    pub(super) elevator_group: ObjectIdentifier,
    /// The identification number of the group (Unsigned8).
    pub(super) group_id: u8,
    /// The identification number of the installation in its group
    /// (Unsigned8).
    pub(super) installation_id: u8,
}

impl GroupMembership {
    /// No group yet: Elevator_Group names Elevator Group instance 4194303,
    /// which Clauses 12.59 and 12.60 use when no Elevator Group lists the
    /// object, and both identification numbers are 0.
    pub(super) fn new() -> Result<Self, Error> {
        Ok(Self {
            elevator_group: ObjectIdentifier::new(
                ObjectType::ELEVATOR_GROUP,
                ObjectIdentifier::MAX_INSTANCE,
            )?,
            group_id: 0,
            installation_id: 0,
        })
    }

    /// The value of `property` if it is one of the three membership rows.
    pub(super) fn read(&self, property: PropertyIdentifier) -> Option<PropertyValue> {
        match property {
            PropertyIdentifier::ELEVATOR_GROUP => {
                Some(PropertyValue::ObjectIdentifier(self.elevator_group))
            }
            PropertyIdentifier::GROUP_ID => Some(PropertyValue::Unsigned(self.group_id.into())),
            PropertyIdentifier::INSTALLATION_ID => {
                Some(PropertyValue::Unsigned(self.installation_id.into()))
            }
            _ => None,
        }
    }

    /// Store a new Elevator_Group, refusing any object type but Elevator
    /// Group with VALUE_OUT_OF_RANGE and leaving the value unchanged.
    pub(super) fn set_elevator_group(&mut self, oid: ObjectIdentifier) -> Result<(), Error> {
        if oid.object_type() != ObjectType::ELEVATOR_GROUP {
            return Err(common::value_out_of_range_error());
        }
        self.elevator_group = oid;
        Ok(())
    }
}

/// The public getters and setters for an object's `membership` field, one
/// pair per membership property. `$object` names the object type in the
/// docs.
macro_rules! group_membership_accessors {
    ($object:literal) => {
        /// The Elevator Group object served as Elevator_Group. Until the
        /// application sets one it names instance 4194303, the reference
        #[doc = concat!("Clauses 12.59 and 12.60 use when no Elevator Group lists this ", $object, ".")]
        pub fn elevator_group(&self) -> ObjectIdentifier {
            self.membership.elevator_group
        }

        /// Set which Elevator Group counts this
        #[doc = concat!($object, " among its Group_Members.")]
        ///
        /// Elevator_Group is read-only over the network, so this is the only
        /// way to change it. A reference to any other object type is refused
        /// with VALUE_OUT_OF_RANGE and the property is left unchanged.
        pub fn set_elevator_group(&mut self, oid: ObjectIdentifier) -> Result<(), Error> {
            self.membership.set_elevator_group(oid)
        }

        /// The identification number of the group, served as Group_ID.
        pub fn group_id(&self) -> u8 {
            self.membership.group_id
        }

        #[doc = concat!("Set the identification number of the group of the ", $object, ".")]
        ///
        /// Group_ID is an Unsigned8 that is read-only over the network, so
        /// this is the only way to change it.
        pub fn set_group_id(&mut self, group_id: u8) {
            self.membership.group_id = group_id;
        }

        #[doc = concat!("The identification number of the ", $object, ", served as Installation_ID.")]
        pub fn installation_id(&self) -> u8 {
            self.membership.installation_id
        }

        #[doc = concat!("Set the identification number of the ", $object, " within its group.")]
        ///
        /// Installation_ID is an Unsigned8 that is read-only over the
        /// network, so this is the only way to change it.
        pub fn set_installation_id(&mut self, installation_id: u8) {
            self.membership.installation_id = installation_id;
        }
    };
}
pub(super) use group_membership_accessors;
