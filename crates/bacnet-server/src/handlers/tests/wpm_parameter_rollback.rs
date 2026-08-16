use super::*;
use bacnet_objects::event_enrollment::{
    EventEnrollmentEvalState, EventEnrollmentObject, EventEnrollmentPending,
};
use bacnet_services::common::BACnetPropertyValue;
use bacnet_services::wpm::{WriteAccessSpecification, WritePropertyMultipleRequest};
use bacnet_types::constructed::{BACnetEventParameter, FaultParameters};

fn failed_wpm(
    db: &mut ObjectDatabase,
    oid: ObjectIdentifier,
    property: PropertyIdentifier,
    value: Vec<u8>,
) {
    let mut read_only = BytesMut::new();
    bacnet_encoding::primitives::encode_app_enumerated(&mut read_only, 0);
    let request = WritePropertyMultipleRequest {
        list_of_write_access_specs: vec![WriteAccessSpecification {
            object_identifier: oid,
            list_of_properties: vec![
                BACnetPropertyValue {
                    property_identifier: property,
                    property_array_index: None,
                    value,
                    priority: None,
                },
                BACnetPropertyValue {
                    property_identifier: PropertyIdentifier::OBJECT_TYPE,
                    property_array_index: None,
                    value: read_only.to_vec(),
                    priority: None,
                },
            ],
        }],
    };
    let mut request_bytes = BytesMut::new();
    request.encode(&mut request_bytes);
    assert!(handle_write_property_multiple(db, &request_bytes).is_err());
}

#[test]
fn wpm_rollback_restores_unencodable_event_parameters_and_pending_state() {
    let mut db = ObjectDatabase::new();
    let mut enrollment = EventEnrollmentObject::new(1, "EE-1", 5).unwrap();
    enrollment.set_event_parameters(BACnetEventParameter::Opaque {
        tag: 200,
        data: vec![0xde],
    });
    let pending = EventEnrollmentPending {
        state: EventState::OFFNORMAL,
        remaining: 2,
        condition: 1,
        params_fingerprint: 2,
    };
    enrollment
        .set_enrollment_eval_state_internal(EventEnrollmentEvalState {
            pending: Some(pending.clone()),
            ..Default::default()
        })
        .unwrap();
    let oid = enrollment.object_identifier();
    assert!(enrollment
        .read_property(PropertyIdentifier::EVENT_PARAMETERS, None)
        .is_err());
    db.add(Box::new(enrollment)).unwrap();

    let mut valid = BytesMut::new();
    bacnet_encoding::constructed::encode_event_parameter(
        &mut valid,
        &BACnetEventParameter::OutOfRange {
            time_delay: 3,
            low_limit: 10.0,
            high_limit: 90.0,
            deadband: 1.0,
        },
    )
    .unwrap();
    failed_wpm(
        &mut db,
        oid,
        PropertyIdentifier::EVENT_PARAMETERS,
        valid.to_vec(),
    );

    let object = db.get(&oid).unwrap();
    assert!(object
        .read_property(PropertyIdentifier::EVENT_PARAMETERS, None)
        .is_err());
    assert_eq!(
        object.enrollment_eval_state_internal().unwrap().pending,
        Some(pending)
    );
}

#[test]
fn wpm_rollback_restores_unencodable_fault_parameters() {
    let mut db = ObjectDatabase::new();
    let mut enrollment = EventEnrollmentObject::new(1, "EE-1", 5).unwrap();
    enrollment.set_fault_parameters(Some(FaultParameters::FaultExtended {
        vendor_id: 1,
        extended_fault_type: 2,
        parameters: vec![0xde],
    }));
    let oid = enrollment.object_identifier();
    assert!(enrollment
        .read_property(PropertyIdentifier::FAULT_PARAMETERS, None)
        .is_err());
    db.add(Box::new(enrollment)).unwrap();

    let mut valid = BytesMut::new();
    bacnet_encoding::constructed::encode_fault_parameters(
        &mut valid,
        &FaultParameters::FaultOutOfRange {
            min_normal: 0.0,
            max_normal: 1.0,
        },
    )
    .unwrap();
    failed_wpm(
        &mut db,
        oid,
        PropertyIdentifier::FAULT_PARAMETERS,
        valid.to_vec(),
    );

    assert!(db
        .get(&oid)
        .unwrap()
        .read_property(PropertyIdentifier::FAULT_PARAMETERS, None)
        .is_err());
}
