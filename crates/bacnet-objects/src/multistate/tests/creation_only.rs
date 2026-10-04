//! Number_Of_States and State_Text written whole as CreateObject initial
//! values (#1429): `initialize_property` checks each and changes nothing on
//! a refusal, and WriteProperty keeps refusing both.

use super::super::*;
use crate::command_source::test_origin;
use PropertyIdentifier as P;

fn code(result: Result<(), Error>) -> ErrorCode {
    match result {
        Err(Error::Protocol { class, code }) => {
            assert_eq!(class, ErrorClass::PROPERTY.to_raw() as u32);
            ErrorCode::from_raw(code as u16)
        }
        other => panic!("expected a PROPERTY refusal, got {other:?}"),
    }
}

fn labels(labels: &[&str]) -> PropertyValue {
    PropertyValue::List(
        labels
            .iter()
            .map(|label| PropertyValue::CharacterString((*label).into()))
            .collect(),
    )
}

fn states(object: &dyn BACnetObject) -> (PropertyValue, PropertyValue) {
    (
        object.read_property(P::NUMBER_OF_STATES, None).unwrap(),
        object.read_property(P::STATE_TEXT, None).unwrap(),
    )
}

fn all_three(number_of_states: u32) -> [Box<dyn BACnetObject>; 3] {
    [
        Box::new(MultiStateInputObject::new(1, "MSI-1", number_of_states).unwrap()),
        Box::new(MultiStateOutputObject::new(1, "MSO-1", number_of_states).unwrap()),
        Box::new(MultiStateValueObject::new(1, "MSV-1", number_of_states).unwrap()),
    ]
}

#[test]
fn a_new_count_resizes_state_text_and_whole_labels_must_match_it() {
    for mut object in all_three(2) {
        let kind = object.object_identifier().object_type();
        assert_eq!(
            object.creation_only_properties(),
            &[P::NUMBER_OF_STATES, P::STATE_TEXT],
            "{kind:?}"
        );
        object
            .initialize_property(P::STATE_TEXT, labels(&["Off", "On"]))
            .unwrap();
        object
            .initialize_property(P::NUMBER_OF_STATES, PropertyValue::Unsigned(3))
            .unwrap();
        // Growth keeps the labels and adds the default one.
        assert_eq!(
            states(&*object),
            (
                PropertyValue::Unsigned(3),
                labels(&["Off", "On", "State 3"])
            ),
            "{kind:?}"
        );
        let before = states(&*object);
        for (value, expected) in [
            (labels(&["a", "b"]), ErrorCode::VALUE_OUT_OF_RANGE),
            (labels(&["a", "b", "c", "d"]), ErrorCode::VALUE_OUT_OF_RANGE),
            (
                PropertyValue::CharacterString("a".into()),
                ErrorCode::VALUE_OUT_OF_RANGE,
            ),
            (
                PropertyValue::List(vec![
                    PropertyValue::CharacterString("a".into()),
                    PropertyValue::Unsigned(2),
                    PropertyValue::CharacterString("c".into()),
                ]),
                ErrorCode::INVALID_DATA_TYPE,
            ),
            (PropertyValue::Null, ErrorCode::INVALID_DATA_TYPE),
        ] {
            assert_eq!(
                code(object.initialize_property(P::STATE_TEXT, value.clone())),
                expected,
                "{kind:?} {value:?}"
            );
            assert_eq!(states(&*object), before, "{kind:?}");
        }
        for (value, expected) in [
            (PropertyValue::Unsigned(0), ErrorCode::VALUE_OUT_OF_RANGE),
            (
                PropertyValue::Unsigned(u64::from(MAX_CREATED_NUMBER_OF_STATES) + 1),
                ErrorCode::VALUE_OUT_OF_RANGE,
            ),
            (
                PropertyValue::Unsigned(u64::from(u32::MAX) + 1),
                ErrorCode::VALUE_OUT_OF_RANGE,
            ),
            (PropertyValue::Enumerated(3), ErrorCode::INVALID_DATA_TYPE),
        ] {
            assert_eq!(
                code(object.initialize_property(P::NUMBER_OF_STATES, value.clone())),
                expected,
                "{kind:?} {value:?}"
            );
            assert_eq!(states(&*object), before, "{kind:?}");
        }
        // The cap itself is a valid count, and one state takes one label.
        object
            .initialize_property(
                P::NUMBER_OF_STATES,
                PropertyValue::Unsigned(MAX_CREATED_NUMBER_OF_STATES.into()),
            )
            .unwrap();
        object
            .initialize_property(P::NUMBER_OF_STATES, PropertyValue::Unsigned(1))
            .unwrap();
        object
            .initialize_property(P::STATE_TEXT, PropertyValue::CharacterString("Only".into()))
            .unwrap();
        assert_eq!(
            states(&*object),
            (PropertyValue::Unsigned(1), labels(&["Only"]))
        );
        // Nothing else is set this way; WriteProperty refuses both wholes.
        assert_eq!(
            code(object.initialize_property(P::DESCRIPTION, PropertyValue::Null)),
            ErrorCode::WRITE_ACCESS_DENIED
        );
        for (property, value) in [
            (P::NUMBER_OF_STATES, PropertyValue::Unsigned(1)),
            (P::STATE_TEXT, labels(&["Only"])),
        ] {
            assert_eq!(
                code(object.write_property(property, None, value, None)),
                ErrorCode::WRITE_ACCESS_DENIED,
                "{kind:?} {property:?}"
            );
        }
    }
}

#[test]
fn a_count_that_would_strand_a_held_state_is_refused() {
    let five = PropertyValue::Unsigned(5);
    let three = PropertyValue::Unsigned(3);

    // Present_Value, commanded or simulated.
    let mut input = MultiStateInputObject::new(1, "MSI-1", 5).unwrap();
    input.set_present_value(5);
    let mut output = MultiStateOutputObject::new(1, "MSO-1", 5).unwrap();
    output
        .write_property_from(
            P::PRESENT_VALUE,
            None,
            five.clone(),
            Some(8),
            &test_origin(),
        )
        .unwrap();
    let mut value = MultiStateValueObject::new(1, "MSV-1", 5).unwrap();
    value
        .write_property_from(
            P::PRESENT_VALUE,
            None,
            five.clone(),
            Some(8),
            &test_origin(),
        )
        .unwrap();
    // Relinquish_Default, and Alarm_Values.
    let mut default = MultiStateValueObject::new(2, "MSV-2", 5).unwrap();
    default.set_relinquish_default(5).unwrap();
    let mut alarms = MultiStateInputObject::new(2, "MSI-2", 5).unwrap();
    alarms.set_alarm_values(vec![1, 5]);
    let objects: [&mut dyn BACnetObject; 5] = [
        &mut input,
        &mut output,
        &mut value,
        &mut default,
        &mut alarms,
    ];
    for object in objects {
        let name = object.object_name().to_owned();
        assert_eq!(
            code(object.initialize_property(P::NUMBER_OF_STATES, three.clone())),
            ErrorCode::VALUE_OUT_OF_RANGE,
            "{name}"
        );
        assert_eq!(
            object.read_property(P::NUMBER_OF_STATES, None).unwrap(),
            five
        );
        // A count that still holds every state is taken.
        object
            .initialize_property(P::NUMBER_OF_STATES, PropertyValue::Unsigned(6))
            .unwrap();
    }

    // A Multi-state Output's Feedback_Value is sensed, not held: it doesn't
    // stop the count, and the object reports the mismatch as a fault.
    let mut output = MultiStateOutputObject::new(3, "MSO-3", 5).unwrap();
    output
        .write_property(P::FEEDBACK_VALUE, None, five, None)
        .unwrap();
    output
        .initialize_property(P::NUMBER_OF_STATES, three)
        .unwrap();
    assert_eq!(
        output.read_property(P::RELIABILITY, None).unwrap(),
        PropertyValue::Enumerated(Reliability::CONFIGURATION_ERROR.to_raw())
    );
}
