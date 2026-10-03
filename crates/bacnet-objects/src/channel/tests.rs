use super::*;
use bacnet_types::enums::{ErrorClass, ErrorCode};
use PropertyIdentifier as P;

fn assert_error<T: std::fmt::Debug>(result: Result<T, Error>, class: ErrorClass, code: ErrorCode) {
    assert!(
        matches!(result, Err(Error::Protocol { class: c, code: e })
            if c == class.to_raw() as u32 && e == code.to_raw() as u32),
        "expected {class:?} / {code:?}, got {result:?}"
    );
}

fn assert_property_error<T: std::fmt::Debug>(result: Result<T, Error>, code: ErrorCode) {
    assert_error(result, ErrorClass::PROPERTY, code);
}

fn oid(object_type: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(object_type, instance).unwrap()
}

fn device(instance: u32) -> ObjectIdentifier {
    oid(ObjectType::DEVICE, instance)
}

/// AV-`instance`'s Present_Value, in this device.
fn member(instance: u32) -> BACnetDeviceObjectPropertyReference {
    BACnetDeviceObjectPropertyReference::new_local(
        oid(ObjectType::ANALOG_VALUE, instance),
        P::PRESENT_VALUE.to_raw(),
    )
}

fn encoded(members: &[BACnetDeviceObjectPropertyReference]) -> Vec<u8> {
    let mut bytes = BytesMut::new();
    for member in members {
        encode_device_object_property_reference(&mut bytes, member);
    }
    bytes.to_vec()
}

/// CH-1 on channel 7 with members AV-1, AV-2 (100 ms) and AV-3 (200 ms).
fn configured() -> ChannelObject {
    let mut channel = ChannelObject::new(1, "CH-1", 7).unwrap();
    channel
        .set_members(vec![member(1), member(2), member(3)])
        .unwrap();
    channel.set_execution_delay(vec![0, 100, 200]).unwrap();
    channel
}

fn read(channel: &ChannelObject, property: PropertyIdentifier) -> PropertyValue {
    channel.read_property(property, None).unwrap()
}

fn write_status(channel: &ChannelObject) -> WriteStatus {
    match read(channel, P::WRITE_STATUS) {
        PropertyValue::Enumerated(raw) => WriteStatus::from_raw(raw),
        other => panic!("Write_Status read {other:?}"),
    }
}

fn write_pv(
    channel: &mut ChannelObject,
    value: PropertyValue,
    priority: Option<u8>,
) -> Result<(), Error> {
    channel.write_property(P::PRESENT_VALUE, None, value, priority)
}

fn distribution(run: &CommandRun) -> &ChannelDistribution {
    match &run.plan {
        RunPlan::Channel(distribution) => distribution,
        other => panic!("a Channel queues a distribution, not {other:?}"),
    }
}

fn unsigned_list(values: &[u64]) -> PropertyValue {
    PropertyValue::List(
        values
            .iter()
            .copied()
            .map(PropertyValue::Unsigned)
            .collect(),
    )
}

#[test]
fn channel_starts_with_null_priority_16_idle_and_group_zero() {
    let channel = ChannelObject::new(4, "CH-4", 11).unwrap();
    assert_eq!(
        read(&channel, P::OBJECT_TYPE),
        PropertyValue::Enumerated(53)
    );
    assert_eq!(read(&channel, P::PRESENT_VALUE), PropertyValue::Null);
    assert_eq!(
        read(&channel, P::LAST_PRIORITY),
        PropertyValue::Unsigned(16)
    );
    assert_eq!(write_status(&channel), WriteStatus::IDLE);
    assert_eq!(
        read(&channel, P::STATUS_FLAGS),
        PropertyValue::BitString {
            unused_bits: 4,
            data: vec![0x00]
        }
    );
    assert_eq!(
        read(&channel, P::OUT_OF_SERVICE),
        PropertyValue::Boolean(false)
    );
    assert_eq!(
        read(&channel, P::CHANNEL_NUMBER),
        PropertyValue::Unsigned(11)
    );
    assert_eq!(read(&channel, P::CONTROL_GROUPS), unsigned_list(&[0]));
    assert_eq!(
        read(&channel, P::LIST_OF_OBJECT_PROPERTY_REFERENCES),
        PropertyValue::List(vec![])
    );
    assert_eq!(
        read(&channel, P::EXECUTION_DELAY),
        PropertyValue::List(vec![])
    );
    // Not served: Reliability is optional and the object has none.
    assert_property_error(
        channel.read_property(P::RELIABILITY, None),
        ErrorCode::UNKNOWN_PROPERTY,
    );
}

#[test]
fn channel_arrays_read_one_element_per_index() {
    let mut channel = configured();
    channel.set_control_groups(vec![27, 0, 14]).unwrap();
    let arrays = [
        (
            P::LIST_OF_OBJECT_PROPERTY_REFERENCES,
            [1, 2, 3].map(|n| PropertyValue::ApplicationData(encoded(&[member(n)]))),
        ),
        (
            P::EXECUTION_DELAY,
            [0, 100, 200].map(PropertyValue::Unsigned),
        ),
        (P::CONTROL_GROUPS, [27, 0, 14].map(PropertyValue::Unsigned)),
    ];
    for (property, elements) in arrays {
        // Arrays on Channel, where a Schedule's reference list is a list.
        assert!(channel.is_array_property(property), "{property:?}");
        assert!(!channel.is_list_property(property), "{property:?}");
        assert_eq!(
            channel.read_property(property, None).unwrap(),
            PropertyValue::List(elements.to_vec()),
            "{property:?}"
        );
        assert_eq!(
            channel.read_property(property, Some(0)).unwrap(),
            PropertyValue::Unsigned(3),
            "{property:?}"
        );
        for (index, element) in elements.iter().enumerate() {
            assert_eq!(
                &channel
                    .read_property(property, Some(index as u32 + 1))
                    .unwrap(),
                element,
                "{property:?}[{}]",
                index + 1
            );
        }
        for index in [4, u32::MAX] {
            assert_property_error(
                channel.read_property(property, Some(index)),
                ErrorCode::INVALID_ARRAY_INDEX,
            );
        }
    }
    // The scalars take no index.
    for property in [P::PRESENT_VALUE, P::CHANNEL_NUMBER, P::WRITE_STATUS] {
        assert!(!channel.is_array_property(property), "{property:?}");
        assert_property_error(
            channel.write_property(property, Some(1), PropertyValue::Unsigned(1), None),
            ErrorCode::PROPERTY_IS_NOT_AN_ARRAY,
        );
    }
}

#[test]
fn channel_present_value_write_queues_its_members_and_goes_in_progress() {
    let mut channel = configured();
    assert!(channel.take_command_run_internal().is_none());
    write_pv(&mut channel, PropertyValue::Real(42.5), Some(9)).unwrap();
    assert_eq!(read(&channel, P::PRESENT_VALUE), PropertyValue::Real(42.5));
    assert_eq!(read(&channel, P::LAST_PRIORITY), PropertyValue::Unsigned(9));
    assert_eq!(write_status(&channel), WriteStatus::IN_PROGRESS);

    let run = channel.take_command_run_internal().unwrap();
    assert!(channel.take_command_run_internal().is_none(), "taken once");
    assert_eq!(run.source, channel.object_identifier());
    assert_eq!(Some(run.generation), channel.command_generation_internal());
    let queued = distribution(&run);
    assert_eq!(queued.value, PropertyValue::Real(42.5));
    assert_eq!(queued.priority, Some(9));
    assert_eq!(
        queued
            .members
            .iter()
            .map(|member| (member.reference.clone(), member.delay_ms))
            .collect::<Vec<_>>(),
        [(member(1), 0), (member(2), 100), (member(3), 200)]
    );

    // Any Present_Value write while the members are written is OBJECT / BUSY
    // and changes nothing.
    assert_error(
        write_pv(&mut channel, PropertyValue::Real(1.0), None),
        ErrorClass::OBJECT,
        ErrorCode::BUSY,
    );
    assert_eq!(read(&channel, P::PRESENT_VALUE), PropertyValue::Real(42.5));
    assert_eq!(read(&channel, P::LAST_PRIORITY), PropertyValue::Unsigned(9));

    assert!(channel.complete_command_run_internal(run.generation, true));
    assert_eq!(write_status(&channel), WriteStatus::SUCCESSFUL);
    assert!(!channel.complete_command_run_internal(run.generation, false));
    assert_eq!(write_status(&channel), WriteStatus::SUCCESSFUL);

    // Without a priority, Last_Priority is 16 and the members get none.
    write_pv(&mut channel, PropertyValue::Null, None).unwrap();
    assert_eq!(
        read(&channel, P::LAST_PRIORITY),
        PropertyValue::Unsigned(16)
    );
    let again = channel.take_command_run_internal().unwrap();
    assert_ne!(again.generation, run.generation);
    assert_eq!(distribution(&again).priority, None);
    assert_eq!(distribution(&again).value, PropertyValue::Null);
    assert!(channel.complete_command_run_internal(again.generation, false));
    assert_eq!(write_status(&channel), WriteStatus::FAILED);
}

#[test]
fn channel_stale_completion_is_ignored() {
    let mut channel = configured();
    write_pv(&mut channel, PropertyValue::Unsigned(3), None).unwrap();
    let run = channel.take_command_run_internal().unwrap();
    assert!(!channel.complete_command_run_internal(run.generation.wrapping_add(1), true));
    assert_eq!(write_status(&channel), WriteStatus::IN_PROGRESS);
    assert!(channel.complete_command_run_internal(run.generation, true));
}

#[test]
fn channel_without_members_stays_idle_and_empty_references_are_skipped() {
    let mut channel = ChannelObject::new(1, "CH-1", 7).unwrap();
    write_pv(&mut channel, PropertyValue::Boolean(true), Some(4)).unwrap();
    assert_eq!(write_status(&channel), WriteStatus::IDLE);
    assert!(channel.take_command_run_internal().is_none());
    assert_eq!(
        read(&channel, P::PRESENT_VALUE),
        PropertyValue::Boolean(true)
    );
    assert_eq!(read(&channel, P::LAST_PRIORITY), PropertyValue::Unsigned(4));

    // Instance 4194303, in the object or the Device, marks a member empty.
    let empty_device = BACnetDeviceObjectPropertyReference {
        device_identifier: Some(device(ObjectIdentifier::WILDCARD_INSTANCE)),
        ..member(2)
    };
    channel
        .set_members(vec![arrays::empty_reference(), empty_device.clone()])
        .unwrap();
    write_pv(&mut channel, PropertyValue::Boolean(false), None).unwrap();
    assert!(channel.take_command_run_internal().is_none());
    assert_eq!(write_status(&channel), WriteStatus::SUCCESSFUL);

    channel
        .set_members(vec![arrays::empty_reference(), member(5), empty_device])
        .unwrap();
    write_pv(&mut channel, PropertyValue::Boolean(true), None).unwrap();
    let run = channel.take_command_run_internal().unwrap();
    assert_eq!(
        distribution(&run)
            .members
            .iter()
            .map(|member| member.reference.clone())
            .collect::<Vec<_>>(),
        [member(5)]
    );
}

#[test]
fn channel_out_of_service_keeps_the_value_from_the_members() {
    let mut channel = configured();
    channel
        .write_property(P::OUT_OF_SERVICE, None, PropertyValue::Boolean(true), None)
        .unwrap();
    assert_eq!(
        read(&channel, P::STATUS_FLAGS),
        PropertyValue::BitString {
            unused_bits: 4,
            data: vec![0x10]
        }
    );
    write_pv(&mut channel, PropertyValue::Real(5.0), Some(3)).unwrap();
    assert_eq!(read(&channel, P::PRESENT_VALUE), PropertyValue::Real(5.0));
    assert_eq!(read(&channel, P::LAST_PRIORITY), PropertyValue::Unsigned(3));
    assert_eq!(write_status(&channel), WriteStatus::IDLE);
    assert!(channel.take_command_run_internal().is_none());

    channel
        .write_property(P::OUT_OF_SERVICE, None, PropertyValue::Boolean(false), None)
        .unwrap();
    write_pv(&mut channel, PropertyValue::Real(6.0), Some(3)).unwrap();
    assert!(channel.take_command_run_internal().is_some());
}

#[test]
fn channel_present_value_takes_a_channel_value_and_a_priority_from_1_to_16() {
    let mut channel = ChannelObject::new(1, "CH-1", 7).unwrap();
    // operation 1 with a target level of 50.0, framed in [0].
    let lighting = vec![0x0E, 0x09, 0x01, 0x1C, 0x42, 0x48, 0x00, 0x00, 0x0F];
    for value in [
        PropertyValue::Signed(-4),
        PropertyValue::Double(1.5),
        PropertyValue::CharacterString("scene".into()),
        PropertyValue::ObjectIdentifier(oid(ObjectType::ANALOG_VALUE, 2)),
        PropertyValue::ApplicationData(lighting.clone()),
    ] {
        write_pv(&mut channel, value.clone(), None).unwrap();
        assert_eq!(read(&channel, P::PRESENT_VALUE), value);
    }
    assert_property_error(
        write_pv(&mut channel, unsigned_list(&[1, 2]), None),
        ErrorCode::INVALID_DATA_TYPE,
    );
    // A context tag other than the lighting command's [0].
    assert_property_error(
        write_pv(
            &mut channel,
            PropertyValue::ApplicationData(vec![0x19, 0x01]),
            None,
        ),
        ErrorCode::INVALID_DATA_TYPE,
    );
    // A lighting command without its operation field.
    assert_property_error(
        write_pv(
            &mut channel,
            PropertyValue::ApplicationData(vec![0x0E, 0x1C, 0x42, 0x48, 0x00, 0x00, 0x0F]),
            None,
        ),
        ErrorCode::INVALID_DATA_ENCODING,
    );
    for priority in [0, 17] {
        assert_property_error(
            write_pv(&mut channel, PropertyValue::Real(1.0), Some(priority)),
            ErrorCode::VALUE_OUT_OF_RANGE,
        );
    }
    assert_eq!(
        read(&channel, P::PRESENT_VALUE),
        PropertyValue::ApplicationData(lighting)
    );
    assert_eq!(
        read(&channel, P::LAST_PRIORITY),
        PropertyValue::Unsigned(16)
    );
}

#[test]
fn channel_member_writes_keep_execution_delay_the_same_size() {
    let mut channel = configured();
    let list = P::LIST_OF_OBJECT_PROPERTY_REFERENCES;
    // A whole write, as the server hands it over: the members' octets back
    // to back. Two members: the delays keep their first two.
    channel
        .write_property(
            list,
            None,
            PropertyValue::ApplicationData(encoded(&[member(8), member(9)])),
            None,
        )
        .unwrap();
    assert_eq!(read(&channel, P::EXECUTION_DELAY), unsigned_list(&[0, 100]));
    // One element.
    channel
        .write_property(
            list,
            Some(2),
            PropertyValue::ApplicationData(encoded(&[member(4)])),
            None,
        )
        .unwrap();
    assert_eq!(
        read(&channel, list),
        PropertyValue::List(vec![
            PropertyValue::ApplicationData(encoded(&[member(8)])),
            PropertyValue::ApplicationData(encoded(&[member(4)])),
        ])
    );
    // Index 0 grows both arrays: empty references and zero delays.
    channel
        .write_property(list, Some(0), PropertyValue::Unsigned(4), None)
        .unwrap();
    assert_eq!(
        channel.read_property(list, Some(4)).unwrap(),
        PropertyValue::ApplicationData(encoded(&[arrays::empty_reference()]))
    );
    assert_eq!(
        read(&channel, P::EXECUTION_DELAY),
        unsigned_list(&[0, 100, 0, 0])
    );
    // Growing Execution_Delay grows the members too; shrinking either
    // shrinks both from the end.
    channel
        .write_property(
            P::EXECUTION_DELAY,
            Some(0),
            PropertyValue::Unsigned(5),
            None,
        )
        .unwrap();
    assert_eq!(
        channel.read_property(list, Some(0)).unwrap(),
        PropertyValue::Unsigned(5)
    );
    channel
        .write_property(P::EXECUTION_DELAY, None, unsigned_list(&[5, 6]), None)
        .unwrap();
    assert_eq!(
        channel.read_property(list, Some(0)).unwrap(),
        PropertyValue::Unsigned(2)
    );
    channel
        .write_property(
            P::EXECUTION_DELAY,
            Some(2),
            PropertyValue::Unsigned(250),
            None,
        )
        .unwrap();
    assert_eq!(read(&channel, P::EXECUTION_DELAY), unsigned_list(&[5, 250]));
    // A one-element array decodes to its single value.
    channel
        .write_property(P::EXECUTION_DELAY, None, PropertyValue::Unsigned(9), None)
        .unwrap();
    assert_eq!(
        read(&channel, list),
        PropertyValue::List(vec![PropertyValue::ApplicationData(encoded(&[member(8)])),])
    );
    channel
        .write_property(list, Some(0), PropertyValue::Unsigned(0), None)
        .unwrap();
    assert_eq!(
        read(&channel, P::EXECUTION_DELAY),
        PropertyValue::List(vec![])
    );
    // An empty whole write empties both.
    channel.set_members(vec![member(1)]).unwrap();
    channel
        .write_property(list, None, PropertyValue::ApplicationData(vec![]), None)
        .unwrap();
    assert_eq!(
        read(&channel, P::EXECUTION_DELAY),
        PropertyValue::List(vec![])
    );
}

#[test]
fn channel_member_writes_refuse_other_devices_bad_indexes_and_oversize() {
    let mut channel = configured();
    let list = P::LIST_OF_OBJECT_PROPERTY_REFERENCES;
    let before = read(&channel, list);
    let remote = BACnetDeviceObjectPropertyReference {
        device_identifier: Some(device(9)),
        ..member(1)
    };
    for (index, value) in [
        (None, encoded(&[member(1), remote.clone()])),
        (Some(1), encoded(std::slice::from_ref(&remote))),
    ] {
        assert_property_error(
            channel.write_property(list, index, PropertyValue::ApplicationData(value), None),
            ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED,
        );
    }
    assert_property_error(
        channel.set_members(vec![remote]),
        ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED,
    );
    assert_property_error(
        channel.write_property(
            list,
            Some(4),
            PropertyValue::ApplicationData(encoded(&[member(4)])),
            None,
        ),
        ErrorCode::INVALID_ARRAY_INDEX,
    );
    assert_property_error(
        channel.write_property(
            list,
            Some(1),
            PropertyValue::ApplicationData(encoded(&[member(4), member(5)])),
            None,
        ),
        ErrorCode::INVALID_DATA_ENCODING,
    );
    // An application tag where a member's [0] object identifier belongs.
    assert_property_error(
        channel.write_property(
            list,
            None,
            PropertyValue::ApplicationData(vec![0x21, 0x01]),
            None,
        ),
        ErrorCode::INVALID_DATA_TYPE,
    );
    assert_property_error(
        channel.write_property(list, None, PropertyValue::Real(1.0), None),
        ErrorCode::INVALID_DATA_TYPE,
    );
    let too_many = MAX_CHANNEL_MEMBERS as u64 + 1;
    for property in [list, P::EXECUTION_DELAY] {
        assert_error(
            channel.write_property(property, Some(0), PropertyValue::Unsigned(too_many), None),
            ErrorClass::RESOURCES,
            ErrorCode::NO_SPACE_TO_WRITE_PROPERTY,
        );
    }
    assert_error(
        channel.set_members(vec![member(1); MAX_CHANNEL_MEMBERS + 1]),
        ErrorClass::RESOURCES,
        ErrorCode::NO_SPACE_TO_WRITE_PROPERTY,
    );
    assert_property_error(
        channel.write_property(
            P::EXECUTION_DELAY,
            Some(1),
            PropertyValue::Unsigned(u64::from(u32::MAX) + 1),
            None,
        ),
        ErrorCode::VALUE_OUT_OF_RANGE,
    );
    assert_property_error(
        channel.set_execution_delay(vec![1, 2]),
        ErrorCode::VALUE_OUT_OF_RANGE,
    );
    assert_eq!(read(&channel, list), before);
    assert_eq!(
        read(&channel, P::EXECUTION_DELAY),
        unsigned_list(&[0, 100, 200])
    );
}

#[test]
fn channel_number_and_control_groups_writes() {
    let mut channel = configured();
    channel
        .write_property(
            P::CHANNEL_NUMBER,
            None,
            PropertyValue::Unsigned(65_535),
            None,
        )
        .unwrap();
    assert_eq!(
        read(&channel, P::CHANNEL_NUMBER),
        PropertyValue::Unsigned(65_535)
    );
    assert_property_error(
        channel.write_property(
            P::CHANNEL_NUMBER,
            None,
            PropertyValue::Unsigned(65_536),
            None,
        ),
        ErrorCode::VALUE_OUT_OF_RANGE,
    );
    assert_property_error(
        channel.write_property(P::CHANNEL_NUMBER, None, PropertyValue::Signed(3), None),
        ErrorCode::INVALID_DATA_TYPE,
    );

    let groups = P::CONTROL_GROUPS;
    channel
        .write_property(groups, None, unsigned_list(&[27, 27, 0]), None)
        .unwrap();
    channel
        .write_property(
            groups,
            Some(3),
            PropertyValue::Unsigned(u32::MAX.into()),
            None,
        )
        .unwrap();
    channel
        .write_property(groups, Some(0), PropertyValue::Unsigned(4), None)
        .unwrap();
    assert_eq!(
        read(&channel, groups),
        unsigned_list(&[27, 27, u32::MAX.into(), 0])
    );
    channel
        .write_property(groups, None, PropertyValue::Unsigned(5), None)
        .unwrap();
    assert_eq!(read(&channel, groups), unsigned_list(&[5]));
    // At least one entry, at most MAX_CONTROL_GROUPS.
    assert_property_error(
        channel.write_property(groups, Some(0), PropertyValue::Unsigned(0), None),
        ErrorCode::VALUE_OUT_OF_RANGE,
    );
    assert_property_error(
        channel.set_control_groups(vec![]),
        ErrorCode::VALUE_OUT_OF_RANGE,
    );
    assert_error(
        channel.write_property(
            groups,
            Some(0),
            PropertyValue::Unsigned(MAX_CONTROL_GROUPS as u64 + 1),
            None,
        ),
        ErrorClass::RESOURCES,
        ErrorCode::NO_SPACE_TO_WRITE_PROPERTY,
    );
    assert_property_error(
        channel.write_property(groups, Some(2), PropertyValue::Unsigned(1), None),
        ErrorCode::INVALID_ARRAY_INDEX,
    );
    assert_property_error(
        channel.write_property(
            groups,
            Some(1),
            PropertyValue::Unsigned(u64::from(u32::MAX) + 1),
            None,
        ),
        ErrorCode::VALUE_OUT_OF_RANGE,
    );
    assert_eq!(read(&channel, groups), unsigned_list(&[5]));
}

#[test]
fn channel_read_only_rows_refuse_writes() {
    let mut channel = configured();
    for property in [
        P::LAST_PRIORITY,
        P::WRITE_STATUS,
        P::STATUS_FLAGS,
        P::OBJECT_TYPE,
    ] {
        assert_property_error(
            channel.write_property(property, None, PropertyValue::Unsigned(1), None),
            ErrorCode::WRITE_ACCESS_DENIED,
        );
    }
    assert_property_error(
        channel.write_property(
            P::ALLOW_GROUP_DELAY_INHIBIT,
            None,
            PropertyValue::Boolean(true),
            None,
        ),
        ErrorCode::UNKNOWN_PROPERTY,
    );
}

#[test]
fn channel_property_list_and_required_rows_follow_table_12_62() {
    let channel = configured();
    assert_eq!(
        channel.property_list().as_ref(),
        [
            P::OBJECT_IDENTIFIER,
            P::OBJECT_NAME,
            P::OBJECT_TYPE,
            P::DESCRIPTION,
            P::PRESENT_VALUE,
            P::LAST_PRIORITY,
            P::WRITE_STATUS,
            P::STATUS_FLAGS,
            P::OUT_OF_SERVICE,
            P::LIST_OF_OBJECT_PROPERTY_REFERENCES,
            P::EXECUTION_DELAY,
            P::CHANNEL_NUMBER,
            P::CONTROL_GROUPS,
        ]
    );
    assert_eq!(
        channel.required_properties().as_ref(),
        [
            P::OBJECT_IDENTIFIER,
            P::OBJECT_NAME,
            P::OBJECT_TYPE,
            P::PRESENT_VALUE,
            P::LAST_PRIORITY,
            P::WRITE_STATUS,
            P::STATUS_FLAGS,
            P::OUT_OF_SERVICE,
            P::LIST_OF_OBJECT_PROPERTY_REFERENCES,
            P::CHANNEL_NUMBER,
            P::CONTROL_GROUPS,
            P::PROPERTY_LIST,
        ]
    );
    for property in channel.property_list().iter() {
        channel
            .read_property(*property, None)
            .unwrap_or_else(|error| panic!("{property:?}: {error:?}"));
    }
    let writable: Vec<_> = channel
        .property_list()
        .iter()
        .copied()
        .filter(|property| channel.is_writable_property(*property))
        .collect();
    assert_eq!(
        writable,
        [
            P::OBJECT_NAME,
            P::DESCRIPTION,
            P::PRESENT_VALUE,
            P::OUT_OF_SERVICE,
            P::LIST_OF_OBJECT_PROPERTY_REFERENCES,
            P::EXECUTION_DELAY,
            P::CHANNEL_NUMBER,
            P::CONTROL_GROUPS,
        ]
    );
    assert!(!channel.supports_cov());
    assert!(!channel.supports_subscribe_cov_property());
    assert!(!channel.is_createable());
    assert!(channel.is_deleteable());
}
