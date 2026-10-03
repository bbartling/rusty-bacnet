use super::*;
use crate::local_device::selected_device;

/// Handle a ReadProperty request against standalone object data.
///
/// Looks up the object and property in the database, encodes the value,
/// and returns the ReadPropertyACK service bytes. This low-level helper has
/// no executor context: a built-in Device follows its declared service profile,
/// including absent or empty COV lists. Running server reads use the executor's
/// property definitions and live subscription table instead.
pub fn handle_read_property(
    db: &ObjectDatabase,
    service_data: &[u8],
    buf: &mut BytesMut,
) -> Result<(), Error> {
    let request = ReadPropertyRequest::decode(service_data)?;
    read_property_request_observed(db, None, &request, buf, |_, _, _| {})
}

/// ReadProperty evaluator over one decoded request. `view` carries executor-owned
/// Device definitions and request-local COV lists; observations carry only execution
/// outcomes, never the read value.
pub(crate) fn read_property_request_observed(
    db: &ObjectDatabase,
    view: Option<&DeviceReadContext<'_>>,
    request: &ReadPropertyRequest,
    buf: &mut BytesMut,
    mut completed: impl FnMut(ObjectIdentifier, &ReadPropertyRequest, &Result<(), Error>),
) -> Result<(), Error> {
    let lookup_oid = resolve_read_target(
        db,
        &request.object_identifier,
        view.and_then(|view| view.registered_port),
    );
    let result = read_property_decoded(db, view, request, lookup_oid, buf);
    completed(lookup_oid, request, &result);
    result
}

/// Evaluate one property read with ReadProperty error precedence: unknown
/// object, then non-array index using the effective property definition, then
/// the executor view or raw object's reader, except that a Group's
/// Present_Value is rebuilt from its members.
pub(crate) fn read_property_value(
    db: &ObjectDatabase,
    view: Option<&DeviceReadContext<'_>>,
    lookup_oid: ObjectIdentifier,
    property: PropertyIdentifier,
    array_index: Option<u32>,
) -> Result<PropertyValue, Error> {
    let object = read_target_object(db, &lookup_oid).ok_or(Error::Protocol {
        class: ErrorClass::OBJECT.to_raw() as u32,
        code: ErrorCode::UNKNOWN_OBJECT.to_raw() as u32,
    })?;

    let served = view.map(|view| view.object(object));
    let object: &dyn bacnet_objects::traits::BACnetObject =
        served.as_ref().map_or(object, |served| served);

    // Clause 15.5.1.3: an array index on a non-array property is rejected
    // with PROPERTY / PROPERTY_IS_NOT_AN_ARRAY. The array/list decision
    // belongs to the object (identifier-static whitelists cannot express the
    // type-dependent identifiers, e.g. ALARM_VALUES), so the handler defers
    // to the trait query.
    if array_index.is_some() && !object.is_array_property(property) {
        return Err(Error::Protocol {
            class: ErrorClass::PROPERTY.to_raw() as u32,
            code: ErrorCode::PROPERTY_IS_NOT_AN_ARRAY.to_raw() as u32,
        });
    }

    group_present_value::read_served_property(db, view, object, property, array_index)
}

fn read_property_decoded(
    db: &ObjectDatabase,
    view: Option<&DeviceReadContext<'_>>,
    request: &ReadPropertyRequest,
    lookup_oid: ObjectIdentifier,
    buf: &mut BytesMut,
) -> Result<(), Error> {
    let value = read_property_value(
        db,
        view,
        lookup_oid,
        request.property_identifier,
        request.property_array_index,
    )?;

    let mut value_buf = BytesMut::new();
    encode_property_value(&mut value_buf, &value)?;

    let ack = ReadPropertyACK {
        object_identifier: lookup_oid,
        property_identifier: request.property_identifier,
        property_array_index: request.property_array_index,
        property_value: value_buf.to_vec(),
    };

    ack.encode(buf);
    Ok(())
}

pub(crate) fn read_target_object<'a>(
    db: &'a ObjectDatabase,
    oid: &ObjectIdentifier,
) -> Option<&'a dyn bacnet_objects::traits::BACnetObject> {
    // An unregistered wildcard is never an ordinary stored object, even if a
    // custom database supplied that reserved identifier.
    if oid.object_type() == ObjectType::NETWORK_PORT && oid.instance_number() == 4194303 {
        return None;
    }
    db.get(oid)
}

fn is_device_wildcard(oid: &ObjectIdentifier) -> bool {
    oid.object_type() == ObjectType::DEVICE && oid.instance_number() == 4194303
}

/// Resolve Device or explicitly registered receiving-port wildcard identity.
pub(crate) fn resolve_read_target(
    db: &ObjectDatabase,
    oid: &ObjectIdentifier,
    registered_port: Option<ObjectIdentifier>,
) -> ObjectIdentifier {
    if oid.object_type() == ObjectType::NETWORK_PORT && oid.instance_number() == 4194303 {
        return registered_port
            .filter(|selected| Some(*selected) == db.registered_bip_port_internal())
            .unwrap_or(*oid);
    }
    if is_device_wildcard(oid) {
        if let Some(device) = selected_device(db) {
            return device;
        }
    }
    *oid
}

/// `(Active_COV_Subscriptions, Active_COV_Multiple_Subscriptions)` that one
/// property reference may select, explicitly or through ALL, REQUIRED or
/// OPTIONAL expansion.
fn live_cov_lists(property: PropertyIdentifier) -> (bool, bool) {
    match property {
        PropertyIdentifier::ACTIVE_COV_SUBSCRIPTIONS => (true, false),
        PropertyIdentifier::ACTIVE_COV_MULTIPLE_SUBSCRIPTIONS => (false, true),
        PropertyIdentifier::ALL | PropertyIdentifier::REQUIRED | PropertyIdentifier::OPTIONAL => {
            (true, true)
        }
        _ => (false, false),
    }
}

fn either(a: (bool, bool), b: (bool, bool)) -> (bool, bool) {
    (a.0 || b.0, a.1 || b.1)
}

/// The selected Device's server-owned COV list when `(lookup_oid, property)`
/// names one; any other read needs no COV table snapshot.
pub(crate) fn active_cov_device(
    db: &ObjectDatabase,
    lookup_oid: ObjectIdentifier,
    property: PropertyIdentifier,
) -> Option<LiveCovSelection> {
    let (active, multiple) = match property {
        PropertyIdentifier::ACTIVE_COV_SUBSCRIPTIONS
        | PropertyIdentifier::ACTIVE_COV_MULTIPLE_SUBSCRIPTIONS => live_cov_lists(property),
        _ => return None,
    };
    let device = selected_device(db).filter(|device| *device == lookup_oid)?;
    Some(LiveCovSelection {
        device,
        active,
        multiple,
    })
}

/// The selected Device's COV lists that any ReadPropertyMultiple reference to
/// it may select, explicitly or through ALL, REQUIRED or OPTIONAL expansion.
/// One snapshot then serves every such row.
pub(crate) fn active_cov_device_for_rpm(
    db: &ObjectDatabase,
    request: &ReadPropertyMultipleRequest,
) -> Option<LiveCovSelection> {
    let spec_lists = |spec: &bacnet_types::constructed::ReadAccessSpecification| {
        spec.list_of_property_references
            .iter()
            .map(|reference| live_cov_lists(reference.property_identifier))
            .fold((false, false), either)
    };
    // Only a request that may select either property pays the Device scan.
    let mut specs = request
        .list_of_read_access_specs
        .iter()
        .map(|spec| (spec, spec_lists(spec)))
        .filter(|(_, (active, multiple))| *active || *multiple)
        .peekable();
    specs.peek()?;
    let device = selected_device(db)?;
    let (active, multiple) = specs
        .filter(|(spec, _)| {
            spec.object_identifier == device || is_device_wildcard(&spec.object_identifier)
        })
        .map(|(_, lists)| lists)
        .fold((false, false), either);
    (active || multiple).then_some(LiveCovSelection {
        device,
        active,
        multiple,
    })
}

fn expand_property_reference(
    object: &dyn bacnet_objects::traits::BACnetObject,
    property_identifier: PropertyIdentifier,
) -> Vec<PropertyIdentifier> {
    let metadata = object.property_metadata();
    if !metadata.is_empty() {
        return match property_identifier {
            PropertyIdentifier::ALL => metadata
                .iter()
                .filter_map(|row| {
                    (row.property_identifier != PropertyIdentifier::PROPERTY_LIST)
                        .then_some(row.property_identifier)
                })
                .collect(),
            PropertyIdentifier::REQUIRED => metadata
                .iter()
                .filter_map(|row| {
                    (row.property_identifier != PropertyIdentifier::PROPERTY_LIST
                        && row.is_required())
                    .then_some(row.property_identifier)
                })
                .collect(),
            PropertyIdentifier::OPTIONAL => metadata
                .iter()
                .filter_map(|row| (!row.is_required()).then_some(row.property_identifier))
                .collect(),
            other => vec![other],
        };
    }

    match property_identifier {
        PropertyIdentifier::ALL => object.property_list().to_vec(),
        PropertyIdentifier::REQUIRED => object.required_properties().to_vec(),
        PropertyIdentifier::OPTIONAL => {
            let required: std::collections::HashSet<PropertyIdentifier> =
                object.required_properties().iter().copied().collect();
            object
                .property_list()
                .iter()
                .copied()
                .filter(|property| !required.contains(property))
                .collect()
        }
        other => vec![other],
    }
}

/// Clause 15.7.3.2.2.2 includes an index only for a declared array property.
/// An unknown object/property or unavailable declaration conservatively omits
/// it. Classification must not probe `read_property` or change error precedence.
pub(super) fn rpm_response_index(
    object: Option<&dyn bacnet_objects::traits::BACnetObject>,
    property: PropertyIdentifier,
    requested: Option<u32>,
) -> Option<u32> {
    let index = requested?;
    let object = object?;
    let metadata = object.property_metadata();
    let present = if metadata.is_empty() {
        object.property_list().contains(&property)
    } else {
        metadata
            .iter()
            .any(|row| row.property_identifier == property)
    };
    (present && object.is_array_property(property)).then_some(index)
}

/// Handle a ReadPropertyMultiple request.
///
/// Per-property errors are returned inline rather than failing the entire request.
/// This legacy low-level helper has no configured service budget. Configured
/// `BACnetServer` dispatch uses a separate bounded implementation.
pub fn handle_read_property_multiple(
    db: &ObjectDatabase,
    service_data: &[u8],
    buf: &mut BytesMut,
) -> Result<(), Error> {
    let request = ReadPropertyMultipleRequest::decode(service_data)?;

    let mut results = Vec::new();
    for spec in &request.list_of_read_access_specs {
        let mut elements = Vec::new();

        let lookup_oid = resolve_read_target(db, &spec.object_identifier, None);
        match read_target_object(db, &lookup_oid) {
            Some(object) => {
                for prop_ref in &spec.list_of_property_references {
                    let prop_ids = expand_property_reference(object, prop_ref.property_identifier);

                    for prop_id in prop_ids {
                        let array_index = if prop_ref.property_identifier == prop_id {
                            prop_ref.property_array_index
                        } else {
                            None
                        };
                        let response_index = rpm_response_index(Some(object), prop_id, array_index);
                        // Same gate as ReadProperty (Clause 15.5.1.3): an
                        // array index on a non-array property fails this
                        // reference inline; sibling references still run.
                        // ALL/REQUIRED/OPTIONAL expansions attach no index,
                        // so they pass through untouched.
                        if array_index.is_some() && !object.is_array_property(prop_id) {
                            elements.push(ReadResultElement {
                                property_identifier: prop_id,
                                property_array_index: response_index,
                                property_value: None,
                                error: Some((
                                    ErrorClass::PROPERTY,
                                    ErrorCode::PROPERTY_IS_NOT_AN_ARRAY,
                                )),
                            });
                            continue;
                        }
                        match group_present_value::read_served_property(
                            db,
                            None,
                            object,
                            prop_id,
                            array_index,
                        ) {
                            Ok(value) => {
                                let mut value_buf = BytesMut::new();
                                match encode_property_value(&mut value_buf, &value) {
                                    Ok(()) => {
                                        elements.push(ReadResultElement {
                                            property_identifier: prop_id,
                                            property_array_index: response_index,
                                            property_value: Some(value_buf.to_vec()),
                                            error: None,
                                        });
                                    }
                                    Err(_) => {
                                        elements.push(ReadResultElement {
                                            property_identifier: prop_id,
                                            property_array_index: response_index,
                                            property_value: None,
                                            error: Some((ErrorClass::PROPERTY, ErrorCode::OTHER)),
                                        });
                                    }
                                }
                            }
                            Err(e) => {
                                let (err_class, err_code) = match &e {
                                    Error::Protocol { class, code } => (
                                        ErrorClass::from_raw(*class as u16),
                                        ErrorCode::from_raw(*code as u16),
                                    ),
                                    _ => (ErrorClass::PROPERTY, ErrorCode::UNKNOWN_PROPERTY),
                                };
                                elements.push(ReadResultElement {
                                    property_identifier: prop_id,
                                    property_array_index: response_index,
                                    property_value: None,
                                    error: Some((err_class, err_code)),
                                });
                            }
                        }
                    }
                }
            }
            None => {
                for prop_ref in &spec.list_of_property_references {
                    elements.push(ReadResultElement {
                        property_identifier: prop_ref.property_identifier,
                        property_array_index: rpm_response_index(
                            None,
                            prop_ref.property_identifier,
                            prop_ref.property_array_index,
                        ),
                        property_value: None,
                        error: Some((ErrorClass::OBJECT, ErrorCode::UNKNOWN_OBJECT)),
                    });
                }
            }
        }

        results.push(ReadAccessResult {
            object_identifier: lookup_oid,
            list_of_results: elements,
        });
    }

    let ack = ReadPropertyMultipleACK {
        list_of_read_access_results: results,
    };
    ack.encode(buf);
    Ok(())
}

#[cfg(test)]
#[path = "tests/rpm_result_index.rs"]
mod rpm_result_index_tests;
