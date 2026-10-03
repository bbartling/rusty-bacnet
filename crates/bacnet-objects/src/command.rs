//! Command object (type 7) per ASHRAE 135-2020 Clause 12.
//!
//! The Command object triggers a set of actions when its present value
//! is written. Each Action element is a typed [`BACnetActionList`].

use bacnet_encoding::constructed::encode_action_list;
use bacnet_types::constructed::BACnetActionList;
use bacnet_types::enums::{ObjectType, PropertyIdentifier, Reliability};
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue, StatusFlags};
use bytes::BytesMut;
use std::borrow::Cow;

use crate::common::{self, read_common_properties};
use crate::traits::BACnetObject;

mod metadata;

/// BACnet Command object — triggers a set of actions on PV write.
pub struct CommandObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    present_value: u64,
    in_process: bool,
    all_writes_successful: bool,
    action: Vec<BACnetActionList>,
    status_flags: StatusFlags,
    reliability: Reliability,
}

impl CommandObject {
    /// Create a new Command object with default values.
    pub fn new(instance: u32, name: impl Into<String>) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::COMMAND, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            present_value: 0,
            in_process: false,
            all_writes_successful: true,
            action: Vec::new(),
            status_flags: StatusFlags::empty(),
            reliability: Reliability::NO_FAULT_DETECTED,
        })
    }

    /// Replace the Action array: element N is the list Present_Value N
    /// selects (Clause 12.10.8).
    ///
    /// Refused with PROPERTY / VALUE_OUT_OF_RANGE, leaving Action as it was,
    /// when a command can't be encoded: a priority outside 1..=16, or a value
    /// with no encoding.
    pub fn set_action(&mut self, action: Vec<BACnetActionList>) -> Result<(), Error> {
        let mut scratch = BytesMut::new();
        for list in &action {
            encode_action_list(&mut scratch, list)
                .map_err(|_| common::value_out_of_range_error())?;
            scratch.clear();
        }
        self.action = action;
        Ok(())
    }
}

impl BACnetObject for CommandObject {
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
        // Table 12-12 has no Out_Of_Service (#1064), and Clause 12.10 holds the
        // OUT_OF_SERVICE flag FALSE.
        if let Some(result) =
            read_common_properties!(self, property, array_index, no_out_of_service)
        {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::OBJECT_TYPE => {
                Ok(PropertyValue::Enumerated(ObjectType::COMMAND.to_raw()))
            }
            p if p == PropertyIdentifier::PRESENT_VALUE => {
                Ok(PropertyValue::Unsigned(self.present_value))
            }
            p if p == PropertyIdentifier::IN_PROCESS => Ok(PropertyValue::Boolean(self.in_process)),
            p if p == PropertyIdentifier::ALL_WRITES_SUCCESSFUL => {
                Ok(PropertyValue::Boolean(self.all_writes_successful))
            }
            // BACnetARRAY[N] of BACnetActionList (Table 12-12): each element
            // goes out framed in its own [0] pair, so one read alone carries
            // the same octets the whole-array read concatenates.
            p if p == PropertyIdentifier::ACTION => {
                let lists = self
                    .action
                    .iter()
                    .map(|list| {
                        let mut encoded = BytesMut::new();
                        encode_action_list(&mut encoded, list)?;
                        Ok(PropertyValue::ApplicationData(encoded.to_vec()))
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                common::read_array(lists, array_index)
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
        if let Some(result) = common::write_description(&mut self.description, property, &value) {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::PRESENT_VALUE => {
                if let PropertyValue::Unsigned(v) = value {
                    self.present_value = v;
                    // In a real system this would trigger action execution
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            p if p == PropertyIdentifier::ACTION => {
                // ACTION is read-only from the network
                Err(common::write_access_denied_error())
            }
            _ => Err(crate::common::unhandled_write_error(
                self.property_metadata().as_ref(),
                property,
                _array_index,
            )),
        }
    }

    fn property_metadata(&self) -> Cow<'_, [crate::property_metadata::PropertyMetadata]> {
        metadata::for_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bacnet_types::constructed::BACnetActionCommand;
    use bacnet_types::enums::{ErrorClass, ErrorCode};

    fn assert_property_error<T: std::fmt::Debug>(result: Result<T, Error>, expected: ErrorCode) {
        assert!(
            matches!(result, Err(Error::Protocol { class, code })
                if class == ErrorClass::PROPERTY.to_raw() as u32
                    && code == expected.to_raw() as u32),
            "expected {expected:?}, got {result:?}"
        );
    }

    #[test]
    fn command_create_and_read_defaults() {
        let cmd = CommandObject::new(1, "CMD-1").unwrap();
        assert_eq!(cmd.object_name(), "CMD-1");
        assert_eq!(
            cmd.read_property(PropertyIdentifier::PRESENT_VALUE, None)
                .unwrap(),
            PropertyValue::Unsigned(0)
        );
        assert_eq!(
            cmd.read_property(PropertyIdentifier::IN_PROCESS, None)
                .unwrap(),
            PropertyValue::Boolean(false)
        );
        assert_eq!(
            cmd.read_property(PropertyIdentifier::ALL_WRITES_SUCCESSFUL, None)
                .unwrap(),
            PropertyValue::Boolean(true)
        );
    }

    #[test]
    fn command_object_type() {
        let cmd = CommandObject::new(1, "CMD-1").unwrap();
        assert_eq!(
            cmd.read_property(PropertyIdentifier::OBJECT_TYPE, None)
                .unwrap(),
            PropertyValue::Enumerated(ObjectType::COMMAND.to_raw())
        );
    }

    #[test]
    fn command_write_present_value() {
        let mut cmd = CommandObject::new(1, "CMD-1").unwrap();
        cmd.write_property(
            PropertyIdentifier::PRESENT_VALUE,
            None,
            PropertyValue::Unsigned(3),
            None,
        )
        .unwrap();
        assert_eq!(
            cmd.read_property(PropertyIdentifier::PRESENT_VALUE, None)
                .unwrap(),
            PropertyValue::Unsigned(3)
        );
    }

    #[test]
    fn command_write_present_value_wrong_type() {
        let mut cmd = CommandObject::new(1, "CMD-1").unwrap();
        let result = cmd.write_property(
            PropertyIdentifier::PRESENT_VALUE,
            None,
            PropertyValue::Real(1.0),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn command_action_read_only() {
        let mut cmd = CommandObject::new(1, "CMD-1").unwrap();
        cmd.set_action(vec![BACnetActionList::default()]).unwrap();
        // Whole or one element, Action has no write route.
        for index in [None, Some(0), Some(1)] {
            let value = PropertyValue::ApplicationData(vec![0x0E, 0x0F]);
            assert_property_error(
                cmd.write_property(PropertyIdentifier::ACTION, index, value, None),
                ErrorCode::WRITE_ACCESS_DENIED,
            );
        }
        assert_eq!(
            cmd.read_property(PropertyIdentifier::ACTION, Some(0))
                .unwrap(),
            PropertyValue::Unsigned(1)
        );
    }

    #[test]
    fn command_read_action_empty() {
        let cmd = CommandObject::new(1, "CMD-1").unwrap();
        assert_eq!(
            cmd.read_property(PropertyIdentifier::ACTION, None).unwrap(),
            PropertyValue::List(vec![])
        );
    }

    fn write_ao1(priority: Option<u8>) -> BACnetActionCommand {
        BACnetActionCommand {
            device_identifier: None,
            object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_OUTPUT, 1).unwrap(),
            property_identifier: PropertyIdentifier::PRESENT_VALUE,
            property_array_index: None,
            property_value: PropertyValue::Real(50.0),
            priority,
            post_delay: None,
            quit_on_failure: false,
            write_successful: true,
        }
    }

    #[test]
    fn command_read_action_serves_one_framed_action_list_per_index() {
        let mut cmd = CommandObject::new(1, "CMD-1").unwrap();
        let lists = vec![
            BACnetActionList {
                commands: vec![write_ao1(Some(8))],
            },
            BACnetActionList::default(),
        ];
        cmd.set_action(lists.clone()).unwrap();
        let elements: Vec<PropertyValue> = lists
            .iter()
            .map(|list| {
                let mut encoded = BytesMut::new();
                encode_action_list(&mut encoded, list).unwrap();
                PropertyValue::ApplicationData(encoded.to_vec())
            })
            .collect();
        assert_eq!(
            cmd.read_property(PropertyIdentifier::ACTION, None).unwrap(),
            PropertyValue::List(elements.clone())
        );
        assert_eq!(
            cmd.read_property(PropertyIdentifier::ACTION, Some(0))
                .unwrap(),
            PropertyValue::Unsigned(2)
        );
        for (index, element) in (1..).zip(&elements) {
            assert_eq!(
                &cmd.read_property(PropertyIdentifier::ACTION, Some(index))
                    .unwrap(),
                element
            );
        }
        // The empty list is its [0] frame alone.
        assert_eq!(
            elements[1],
            PropertyValue::ApplicationData(vec![0x0E, 0x0F])
        );
        for index in [3, u32::MAX] {
            assert_property_error(
                cmd.read_property(PropertyIdentifier::ACTION, Some(index)),
                ErrorCode::INVALID_ARRAY_INDEX,
            );
        }
    }

    #[test]
    fn command_set_action_refuses_a_priority_outside_one_to_sixteen() {
        let mut cmd = CommandObject::new(1, "CMD-1").unwrap();
        let kept = vec![BACnetActionList {
            commands: vec![write_ao1(Some(16))],
        }];
        cmd.set_action(kept).unwrap();
        let before = cmd.read_property(PropertyIdentifier::ACTION, None).unwrap();
        for priority in [0, 17] {
            let refused = vec![BACnetActionList {
                commands: vec![write_ao1(Some(1)), write_ao1(Some(priority))],
            }];
            assert_property_error(cmd.set_action(refused), ErrorCode::VALUE_OUT_OF_RANGE);
            assert_eq!(
                cmd.read_property(PropertyIdentifier::ACTION, None).unwrap(),
                before
            );
        }
    }

    #[test]
    fn command_property_list() {
        let cmd = CommandObject::new(1, "CMD-1").unwrap();
        let list = cmd.property_list();
        assert!(list.contains(&PropertyIdentifier::PRESENT_VALUE));
        assert!(list.contains(&PropertyIdentifier::IN_PROCESS));
        assert!(list.contains(&PropertyIdentifier::ALL_WRITES_SUCCESSFUL));
        assert!(list.contains(&PropertyIdentifier::ACTION));
    }
}
