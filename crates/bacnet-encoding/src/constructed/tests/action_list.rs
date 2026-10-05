//! BACnetActionList / BACnetActionCommand vectors, worked out by hand from the
//! Clause 21 context tags and the Clause 20.2 encodings rather than produced
//! by this codec.
use super::*;
use bacnet_types::constructed::{BACnetActionCommand, BACnetActionList};
use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::primitives::PropertyValue;

fn oid(object_type: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(object_type, instance).unwrap()
}

/// A local write of 50.0 to AO-1 Present_Value at priority 8.
fn local_command() -> (BACnetActionCommand, &'static [u8]) {
    (
        BACnetActionCommand {
            device_identifier: None,
            object_identifier: oid(ObjectType::ANALOG_OUTPUT, 1),
            property_identifier: PropertyIdentifier::PRESENT_VALUE,
            property_array_index: None,
            property_value: PropertyValue::Real(50.0),
            priority: Some(8),
            post_delay: None,
            quit_on_failure: false,
            write_successful: true,
        },
        &[
            0x1C, 0x00, 0x40, 0x00, 0x01, // [1] AO-1
            0x29, 0x55, // [2] Present_Value
            0x4E, 0x44, 0x42, 0x48, 0x00, 0x00, 0x4F, // [4] REAL 50.0
            0x59, 0x08, // [5] priority 8
            0x79, 0x00, // [7] FALSE
            0x89, 0x01, // [8] TRUE
        ],
    )
}

/// A remote indexed write with a post delay and every optional member but
/// the priority.
fn remote_command() -> (BACnetActionCommand, &'static [u8]) {
    (
        BACnetActionCommand {
            device_identifier: Some(oid(ObjectType::DEVICE, 9)),
            object_identifier: oid(ObjectType::BINARY_VALUE, 3),
            property_identifier: PropertyIdentifier::STATE_TEXT,
            property_array_index: Some(3),
            property_value: PropertyValue::Enumerated(1),
            priority: None,
            post_delay: Some(300),
            quit_on_failure: true,
            write_successful: false,
        },
        &[
            0x0C, 0x02, 0x00, 0x00, 0x09, // [0] Device 9
            0x1C, 0x01, 0x40, 0x00, 0x03, // [1] BV-3
            0x29, 0x6E, // [2] State_Text (110)
            0x39, 0x03, // [3] index 3
            0x4E, 0x91, 0x01, 0x4F, // [4] ENUMERATED 1
            0x6A, 0x01, 0x2C, // [6] 300
            0x79, 0x01, // [7] TRUE
            0x89, 0x00, // [8] FALSE
        ],
    )
}

#[test]
fn action_command_golden_vectors_round_trip() {
    for (command, bytes) in [local_command(), remote_command()] {
        let mut encoded = BytesMut::new();
        encode_action_command(&mut encoded, &command).unwrap();
        assert_eq!(encoded.as_ref(), bytes);
        let (decoded, end) = decode_action_command(bytes, 0).unwrap();
        assert_eq!(decoded, command);
        assert_eq!(end, bytes.len());
    }
}

#[test]
fn action_lists_frame_in_tag_zero_and_decode_one_array_element_at_a_time() {
    let (local, local_bytes) = local_command();
    let (remote, remote_bytes) = remote_command();
    let both = BACnetActionList {
        commands: vec![local, remote],
    };
    let empty = BACnetActionList::default();

    let mut array = BytesMut::new();
    encode_action_list(&mut array, &both).unwrap();
    encode_action_list(&mut array, &empty).unwrap();

    let mut expected = vec![0x0E];
    expected.extend_from_slice(local_bytes);
    expected.extend_from_slice(remote_bytes);
    expected.extend_from_slice(&[0x0F, 0x0E, 0x0F]);
    assert_eq!(array.as_ref(), expected);

    let (first, next) = decode_action_list(&array, 0).unwrap();
    assert_eq!(first, both);
    let (second, end) = decode_action_list(&array, next).unwrap();
    assert_eq!(second, empty);
    assert_eq!(end, array.len());
    // A list whose closing tag is missing is truncated.
    assert!(decode_action_list(&array[..next - 1], 0).is_err());
    // A bare command is not a list.
    assert!(decode_action_list(local_bytes, 0).is_err());
}

#[test]
fn action_command_values_keep_lists_and_context_tagged_elements() {
    let (mut command, _) = local_command();
    for value in [
        PropertyValue::List(vec![]),
        PropertyValue::List(vec![PropertyValue::Unsigned(1), PropertyValue::Unsigned(2)]),
        // A framed value goes out verbatim and comes back the same.
        PropertyValue::ApplicationData(vec![0x0E, 0x21, 0x07, 0x0F]),
    ] {
        command.property_value = value;
        let mut encoded = BytesMut::new();
        encode_action_command(&mut encoded, &command).unwrap();
        let (decoded, end) = decode_action_command(&encoded, 0).unwrap();
        assert_eq!(decoded, command);
        assert_eq!(end, encoded.len());
    }
}

#[test]
fn action_command_priority_outside_one_to_sixteen_is_refused_both_ways() {
    let (mut command, bytes) = local_command();
    for priority in [0, 17, u8::MAX] {
        command.priority = Some(priority);
        let mut untouched = BytesMut::from(&[0xAA][..]);
        assert!(encode_action_command(&mut untouched, &command).is_err());
        assert_eq!(untouched.as_ref(), &[0xAA]);
        let list = BACnetActionList {
            commands: vec![local_command().0, command.clone()],
        };
        assert!(encode_action_list(&mut untouched, &list).is_err());
        assert_eq!(untouched.as_ref(), &[0xAA]);
    }
    // The priority octet sits after [5]'s tag at offset 15.
    for wire in [0u8, 17] {
        let mut altered = bytes.to_vec();
        altered[15] = wire;
        assert!(decode_action_command(&altered, 0).is_err());
    }
    let mut wide = bytes[..14].to_vec();
    wide.extend_from_slice(&[0x5A, 0x01, 0x01, 0x79, 0x00, 0x89, 0x01]);
    assert!(decode_action_command(&wide, 0).is_err());
}

#[test]
fn action_command_rejects_missing_members_and_bad_forms() {
    let (_, bytes) = local_command();
    // Truncated anywhere before the last octet.
    for cut in 0..bytes.len() {
        assert!(
            decode_action_command(&bytes[..cut], 0).is_err(),
            "cut {cut}"
        );
    }
    // No object identifier: the command opens on [2].
    assert!(decode_action_command(&bytes[5..], 0).is_err());
    // No value frame: [5] follows [2].
    let mut no_value = bytes[..7].to_vec();
    no_value.extend_from_slice(&bytes[14..]);
    assert!(decode_action_command(&no_value, 0).is_err());
    // write-successful [8] missing.
    assert!(decode_action_command(&bytes[..bytes.len() - 2], 0).is_err());
    // A BOOLEAN of 2.
    let mut bad_flag = bytes.to_vec();
    *bad_flag.last_mut().unwrap() = 2;
    assert!(decode_action_command(&bad_flag, 0).is_err());
    // A post delay wider than Unsigned32.
    let mut wide_delay = bytes[..16].to_vec();
    wide_delay.extend_from_slice(&[0x6D, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]);
    wide_delay.extend_from_slice(&bytes[16..]);
    assert!(decode_action_command(&wide_delay, 0).is_err());
}

#[test]
fn members_cut_short_are_a_short_buffer() {
    let (_, local) = local_command();
    let (_, remote) = remote_command();
    for bytes in [local, remote] {
        assert_members_cut_short("BACnetActionCommand", bytes, |data| {
            decode_action_command(data, 0)
        });
    }
    let list = [&[0x0E][..], local, remote, &[0x0F]].concat();
    let framed = assert_members_cut_short("BACnetActionList", &list, |data| {
        decode_action_list(data, 0)
    });
    assert!(framed > 0);
}
