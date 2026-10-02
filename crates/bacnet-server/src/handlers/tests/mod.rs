use super::*;
use bacnet_objects::analog::AnalogInputObject;
use bacnet_objects::traits::BACnetObject;
use bacnet_services::wpm::WritePropertyMultipleRequest;

fn make_db_with_ai() -> ObjectDatabase {
    let mut db = ObjectDatabase::new();
    let mut ai = AnalogInputObject::new(1, "AI-1", 62).unwrap();
    ai.set_present_value(72.5);
    db.add(Box::new(ai)).unwrap();
    db
}

fn make_db_with_msi() -> ObjectDatabase {
    let mut db = ObjectDatabase::new();
    db.add(Box::new(
        bacnet_objects::multistate::MultiStateInputObject::new(1, "MSI-1", 3).unwrap(),
    ))
    .unwrap();
    db
}

fn make_db_with_device_and_ai() -> ObjectDatabase {
    let mut db = crate::server::clocked_test_database();
    let device = bacnet_objects::device::DeviceObject::new(bacnet_objects::device::DeviceConfig {
        instance: 1,
        name: "TestDevice".into(),
        ..Default::default()
    })
    .unwrap();
    db.add(Box::new(device)).unwrap();
    db.add(Box::new(AnalogInputObject::new(1, "AI-1", 62).unwrap()))
        .unwrap();
    db
}

/// The class, code and First Failed Element Number an AddListElement,
/// RemoveListElement or CreateObject refusal goes out with: zero unless the
/// handler named an element of the request.
fn list_refusal(result: Result<(), Error>) -> (ErrorClass, ErrorCode, u32) {
    let (class, code, element) = match result {
        Err(Error::Protocol { class, code }) => (class, code, 0),
        Err(Error::Structured {
            class,
            code,
            detail,
        }) => match *detail {
            ErrorDetail::FirstFailedElementNumber(element) => (class, code, element),
            other => panic!("expected an element number, got {other:?}"),
        },
        other => panic!("expected a protocol refusal, got {other:?}"),
    };
    (
        ErrorClass::from_raw(class as u16),
        ErrorCode::from_raw(code as u16),
        element,
    )
}

mod access_door_oos_writes;
mod access_required_rows;
mod access_typed_values;
mod acknowledge_alarm;
mod acknowledge_alarm_ee;
mod alarm_summary_projection;
mod alert_enrollment;
mod array_index_gating;
mod async_dcc;
mod atomic_read_file_budget;
mod atomic_write_file_budget;
mod audit_log_query;
mod audit_recipient_writes;
mod binary_lighting_operations;
mod binary_lighting_relinquish_default;
mod calendar_date_list;
mod cov_multiple_admission;
mod cov_multiple_parameters;
mod cov_property_parameters;
mod cov_request_parameters;
mod detection_enable_summary;
mod device_description_writes;
mod device_event;
mod elevator_landing_calls;
mod elevator_properties;
mod enrollment_summary_budget;
mod enrollment_summary_filters;
mod enrollment_summary_recipients;
mod enrollment_summary_strict;
mod enrollment_summary_support;
mod escalator_writes;
mod file_access_method;
mod file_empty_eof;
mod file_metadata;
mod file_persistence;
mod file_storage_hook;
mod framed_properties;
mod get_event_information_projection;
mod indexed_write_presence;
mod life_safety_cov;
mod life_safety_mode_writes;
mod life_safety_oos_writes;
mod life_safety_operation;
mod life_safety_reset;
mod lighting_required_rows;
mod list_element_edits;
mod list_element_recipients;
mod list_element_targets;
mod loop_properties;
mod multi_element_writes;
mod passwords;
mod property_metadata;
mod pulse_converter_writes;
mod read_event_arrays;
mod read_range;
mod read_range_time;
mod read_rpm;
mod reference_writes;
mod scalar_null_writes;
mod staging_writes;
mod undefined_property_rows;
mod wpm_create_alarm;
mod wpm_prefix_commit;
mod write_cov_who;
mod write_property_name;
mod write_validation;

// Isolated handler fixtures explicitly assert a standalone writer. Live ingress
// derivation is tested separately through the running server's wire dispatcher.
fn sourced_wp(db: &mut ObjectDatabase, data: &[u8]) -> Result<ObjectIdentifier, Error> {
    handle_write_property_observed(
        db,
        data,
        None,
        None,
        Some(&crate::command_source::test_origin()),
    )
}
fn sourced_wpm(db: &mut ObjectDatabase, data: &[u8]) -> Result<Vec<ObjectIdentifier>, Error> {
    let mut snapshots = crate::life_safety_cov::LifeSafetyCovSnapshots::default();
    match handle_write_property_multiple_observed(
        db,
        data,
        &mut snapshots,
        None,
        None,
        None,
        Some(&crate::command_source::test_origin()),
    ) {
        WritePropertyMultipleOutcome::Success { committed_oids } => Ok(committed_oids),
        WritePropertyMultipleOutcome::Error { error, .. } => Err(error),
        WritePropertyMultipleOutcome::Reject { reason } => Err(Error::Reject {
            reason: reason.to_raw(),
        }),
    }
}
