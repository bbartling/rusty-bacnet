//! SourceReporter forwards the Averaging application route and its property
//! COV admission (#1083) instead of inheriting the trait defaults.
use super::*;
use bacnet_objects::averaging::AveragingObject;

#[test]
fn averaging_sample_route_and_property_cov_admission_survive_wrapping() {
    let mut object: Box<dyn BACnetObject> = Box::new(AveragingObject::new(1, "AVG-1").unwrap());
    let owner = bacnet_objects::database::AuditOwnership::for_source(
        oid(ObjectType::DEVICE, 123),
        selected(),
    );
    source_reporter::install(&mut object, &owner).unwrap();

    assert!(!object.supports_cov());
    assert!(object.supports_subscribe_cov_property());
    assert!(object.supports_cov_property(PropertyIdentifier::AVERAGE_VALUE));
    for sample in [PropertyValue::Real(3.0), PropertyValue::Unsigned(5)] {
        object.add_averaging_sample_internal(sample).unwrap();
    }
    assert_eq!(
        object
            .read_property(PropertyIdentifier::AVERAGE_VALUE, None)
            .unwrap(),
        PropertyValue::Real(4.0)
    );
    assert_eq!(
        object
            .read_property(PropertyIdentifier::VALID_SAMPLES, None)
            .unwrap(),
        PropertyValue::Unsigned(2)
    );
}
