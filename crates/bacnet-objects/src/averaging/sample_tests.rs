//! The application route that feeds a stored Averaging object (#1083).
//!
//! `add_averaging_sample_internal` takes each sample the application took and
//! converts it to REAL as Clause 12.5 describes, so a running server can feed
//! the object without reaching its concrete type.
use super::*;
use bacnet_types::enums::{ErrorClass, ErrorCode};

fn read(avg: &AveragingObject, property: PropertyIdentifier) -> PropertyValue {
    avg.read_property(property, None).unwrap()
}

/// `(minimum, maximum, average, attempted, valid)` as read.
fn statistics(avg: &AveragingObject) -> [PropertyValue; 5] {
    [
        read(avg, PropertyIdentifier::MINIMUM_VALUE),
        read(avg, PropertyIdentifier::MAXIMUM_VALUE),
        read(avg, PropertyIdentifier::AVERAGE_VALUE),
        read(avg, PropertyIdentifier::ATTEMPTED_SAMPLES),
        read(avg, PropertyIdentifier::VALID_SAMPLES),
    ]
}

fn assert_error(error: Error, class: ErrorClass, code: ErrorCode) {
    assert!(
        matches!(error, Error::Protocol { class: c, code: e }
            if c == class.to_raw() as u32 && e == code.to_raw() as u32),
        "expected {class:?}/{code:?}, got {error:?}"
    );
}

#[test]
fn averaging_sample_hook_converts_each_sampled_datatype_to_real() {
    let mut avg = AveragingObject::new(1, "AVG-1").unwrap();
    for sample in [
        PropertyValue::Real(2.5),
        PropertyValue::Unsigned(9),
        PropertyValue::Signed(-4),
        PropertyValue::Enumerated(3),
        PropertyValue::Boolean(true),
        PropertyValue::Boolean(false),
    ] {
        avg.add_averaging_sample_internal(sample).unwrap();
    }
    // 2.5 + 9 - 4 + 3 + 1 + 0 = 11.5 over six samples.
    let [minimum, maximum, average, attempted, valid] = statistics(&avg);
    assert_eq!(minimum, PropertyValue::Real(-4.0));
    assert_eq!(maximum, PropertyValue::Real(9.0));
    let PropertyValue::Real(average) = average else {
        panic!("Average_Value is a REAL: {average:?}");
    };
    assert!((average - 11.5 / 6.0).abs() < 1e-5, "{average}");
    assert_eq!(attempted, PropertyValue::Unsigned(6));
    assert_eq!(valid, PropertyValue::Unsigned(6));
}

#[test]
fn averaging_sample_hook_refuses_other_datatypes_and_non_finite_reals() {
    let mut avg = AveragingObject::new(1, "AVG-1").unwrap();
    avg.add_averaging_sample_internal(PropertyValue::Real(20.0))
        .unwrap();
    let before = statistics(&avg);
    for (value, code) in [
        (PropertyValue::Double(1.0), ErrorCode::INVALID_DATA_TYPE),
        (PropertyValue::Null, ErrorCode::INVALID_DATA_TYPE),
        (
            PropertyValue::CharacterString("21".into()),
            ErrorCode::INVALID_DATA_TYPE,
        ),
        (
            PropertyValue::List(vec![PropertyValue::Real(1.0)]),
            ErrorCode::INVALID_DATA_TYPE,
        ),
        (PropertyValue::Real(f32::NAN), ErrorCode::VALUE_OUT_OF_RANGE),
        (
            PropertyValue::Real(f32::INFINITY),
            ErrorCode::VALUE_OUT_OF_RANGE,
        ),
        (
            PropertyValue::Real(f32::NEG_INFINITY),
            ErrorCode::VALUE_OUT_OF_RANGE,
        ),
    ] {
        let error = avg.add_averaging_sample_internal(value).unwrap_err();
        assert_error(error, ErrorClass::PROPERTY, code);
    }
    // The direct setter applies the same finite check.
    let error = avg.add_sample(f32::NAN).unwrap_err();
    assert_error(error, ErrorClass::PROPERTY, ErrorCode::VALUE_OUT_OF_RANGE);
    assert_eq!(
        statistics(&avg),
        before,
        "a refused sample counts as neither attempted nor valid"
    );
}

#[test]
fn averaging_sample_hook_is_refused_by_other_objects() {
    let mut av = crate::analog::AnalogValueObject::new(1, "AV-1", 62).unwrap();
    let error = av
        .add_averaging_sample_internal(PropertyValue::Real(1.0))
        .unwrap_err();
    assert_error(
        error,
        ErrorClass::OBJECT,
        ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED,
    );
}

#[test]
fn averaging_takes_property_cov_subscriptions_but_not_subscribe_cov() {
    let avg = AveragingObject::new(1, "AVG-1").unwrap();
    assert!(!avg.supports_cov(), "Table 13-1 has no Averaging row");
    assert!(avg.supports_subscribe_cov_property());
    for property in [
        PropertyIdentifier::MINIMUM_VALUE,
        PropertyIdentifier::MAXIMUM_VALUE,
        PropertyIdentifier::AVERAGE_VALUE,
        PropertyIdentifier::ATTEMPTED_SAMPLES,
        PropertyIdentifier::VALID_SAMPLES,
    ] {
        assert!(avg.supports_cov_property(property), "{property:?}");
    }
    // Objects that take SubscribeCOV keep taking property subscriptions, and
    // objects that take neither still refuse both.
    let av = crate::analog::AnalogValueObject::new(1, "AV-1", 62).unwrap();
    assert!(av.supports_cov() && av.supports_subscribe_cov_property());
    let file = crate::file::FileObject::new(1, "FILE-1", "text/plain").unwrap();
    assert!(!file.supports_cov() && !file.supports_subscribe_cov_property());
    assert!(!file.supports_cov_property(PropertyIdentifier::FILE_SIZE));
}
