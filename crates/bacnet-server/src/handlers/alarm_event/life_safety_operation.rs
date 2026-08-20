//! LifeSafetyOperation service handler.
//!
use super::super::*;
use bacnet_objects::traits::LifeSafetyOperationEffect;
use bacnet_services::life_safety::LifeSafetyOperationRequest;
use bacnet_types::enums::{ErrorClass, ErrorCode, LifeSafetyOperation};

/// Handle a LifeSafetyOperation request.
///
/// Targeted requests return the exact Clause 13.13 object error. Requests
/// without an Object Identifier attempt every object and retain successful
/// per-object mutations. Returned identifiers are objects whose state changed.
pub fn handle_life_safety_operation(
    db: &mut ObjectDatabase,
    request: &LifeSafetyOperationRequest,
) -> Result<Vec<ObjectIdentifier>, Error> {
    validate_life_safety_operation(request.request)?;

    if let Some(oid) = request.object_identifier {
        let object = db
            .get_mut(&oid)
            .ok_or_else(|| life_safety_error(ErrorClass::OBJECT, ErrorCode::UNKNOWN_OBJECT))?;
        return match object.apply_life_safety_operation(request.request)? {
            LifeSafetyOperationEffect::Applied => Ok(vec![oid]),
            LifeSafetyOperationEffect::AlreadyApplied => Ok(Vec::new()),
        };
    }

    let mut object_ids = db.list_objects();
    object_ids.sort_by_key(|oid| (oid.object_type().to_raw(), oid.instance_number()));
    let attempted = object_ids.len();
    let mut changed = Vec::new();
    let mut already_applied = 0usize;
    let mut failed = 0usize;
    for oid in object_ids {
        let Some(object) = db.get_mut(&oid) else {
            continue;
        };
        match object.apply_life_safety_operation(request.request) {
            Ok(LifeSafetyOperationEffect::Applied) => changed.push(oid),
            Ok(LifeSafetyOperationEffect::AlreadyApplied) => already_applied += 1,
            Err(_) => failed += 1,
        }
    }
    tracing::debug!(
        operation = request.request.to_raw(),
        attempted,
        applied = changed.len(),
        already_applied,
        failed,
        "completed all-applicable LifeSafetyOperation"
    );
    Ok(changed)
}

/// Validate the standard operations accepted by the service.
///
/// Built-in reset execution remains unavailable until application-executor and
/// duplicate-response semantics are defined. A targeted built-in object returns
/// the specified unsupported-operation error from its object hook. A request
/// without an Object Identifier still performs the Clause 13.13 all-applicable
/// attempt and returns Result(+), even when every built-in object rejects reset.
pub fn validate_life_safety_operation(operation: LifeSafetyOperation) -> Result<(), Error> {
    if (LifeSafetyOperation::SILENCE.to_raw()..=LifeSafetyOperation::UNSILENCE_VISUAL.to_raw())
        .contains(&operation.to_raw())
    {
        Ok(())
    } else {
        Err(life_safety_error(
            ErrorClass::OBJECT,
            ErrorCode::VALUE_OUT_OF_RANGE,
        ))
    }
}

pub(crate) fn life_safety_error(class: ErrorClass, code: ErrorCode) -> Error {
    Error::Protocol {
        class: class.to_raw() as u32,
        code: code.to_raw() as u32,
    }
}
