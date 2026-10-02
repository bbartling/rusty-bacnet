use super::*;

/// Handle a WhoHas request and return an IHave response if we have the object.
///
/// Returns `Some(IHaveRequest)` if we have the requested object, `None` otherwise.
pub fn handle_who_has(
    db: &ObjectDatabase,
    service_data: &[u8],
    device_oid: ObjectIdentifier,
) -> Result<Option<IHaveRequest>, Error> {
    let request = WhoHasRequest::decode(service_data)?;

    let instance = device_oid.instance_number();
    if let (Some(low), Some(high)) = (request.low_limit, request.high_limit) {
        if instance < low || instance > high {
            return Ok(None);
        }
    }

    match &request.object {
        WhoHasObject::Identifier(oid) => {
            if let Some(obj) = db.get(oid) {
                return Ok(Some(IHaveRequest {
                    device_identifier: device_oid,
                    object_identifier: *oid,
                    object_name: obj.object_name().to_string(),
                }));
            }
        }
        WhoHasObject::Name(name) => {
            for (oid, obj) in db.iter_objects() {
                if obj.object_name() == name {
                    return Ok(Some(IHaveRequest {
                        device_identifier: device_oid,
                        object_identifier: oid,
                        object_name: name.clone(),
                    }));
                }
            }
        }
    }

    Ok(None)
}

/// Handle a CreateObject request.
///
/// Supports creating objects by type (server picks instance) or by identifier.
/// Returns the encoded ObjectIdentifier of the created object (ComplexAck payload).
/// A refused initial value is `Error::Structured` naming its position in the
/// List of Initial Values (Clause 15.3.1.3); any other refusal is
/// `Error::Protocol` or a decoding error.
pub fn handle_create_object(
    db: &mut ObjectDatabase,
    service_data: &[u8],
    buf: &mut BytesMut,
) -> Result<(), Error> {
    handle_create_object_observed(db, service_data, buf, &mut None, None)
        .map_err(CreateObjectRefusal::into_error)
}

/// Why the CreateObject handler refused a request.
#[derive(Debug)]
pub(crate) enum CreateObjectRefusal {
    /// The request, or one of its initial values, does not decode: an invalid
    /// request rather than an executed one, so it is not audited.
    Malformed(Error),
    /// The object could not be created or initialized.
    Failed(Error),
}

impl CreateObjectRefusal {
    pub(crate) fn into_error(self) -> Error {
        match self {
            Self::Malformed(error) | Self::Failed(error) => error,
        }
    }

    /// The refusal of the initial value at `position` (from 1), which names
    /// it. An undecodable value is an encoding invalid for the property.
    fn of_initial_value(self, position: u32) -> Self {
        let named = |class, code| {
            Error::protocol(
                class,
                code,
                Some(ErrorDetail::FirstFailedElementNumber(position)),
            )
        };
        match self {
            Self::Malformed(Error::Decoding { .. }) => Self::Malformed(named(
                ErrorClass::PROPERTY.to_raw() as u32,
                ErrorCode::INVALID_DATA_ENCODING.to_raw() as u32,
            )),
            Self::Failed(
                Error::Protocol { class, code } | Error::Structured { class, code, .. },
            ) => Self::Failed(named(class, code)),
            other => other,
        }
    }
}

/// Preserve the public handler's result while exposing only the actual requested,
/// allocated candidate, or final identity. Before by-type allocation it is absent.
pub(crate) fn handle_create_object_observed(
    db: &mut ObjectDatabase,
    service_data: &[u8],
    buf: &mut BytesMut,
    target: &mut Option<ObjectIdentifier>,
    command_origin: Option<&bacnet_objects::command_source::CommandOrigin>,
) -> Result<(), CreateObjectRefusal> {
    *target = None;
    let request =
        CreateObjectRequest::decode(service_data).map_err(CreateObjectRefusal::Malformed)?;
    if let ObjectSpecifier::Identifier(oid) = request.object_specifier {
        *target = Some(oid);
    }
    let created_oid = create(db, &request, target).map_err(CreateObjectRefusal::Failed)?;

    // Apply initial values; on failure, remove the created object.
    for (position, pv) in (1u32..).zip(&request.list_of_initial_values) {
        if let Err(refusal) = initialize(db, created_oid, pv, command_origin) {
            let _ = db.remove(&created_oid);
            return Err(refusal.of_initial_value(position));
        }
    }

    bacnet_encoding::primitives::encode_app_object_id(buf, &created_oid);
    Ok(())
}

/// Create the requested object with its default values, setting `target` to
/// its identifier once one is known.
fn create(
    db: &mut ObjectDatabase,
    request: &CreateObjectRequest,
    target: &mut Option<ObjectIdentifier>,
) -> Result<ObjectIdentifier, Error> {
    const MAX_OBJECTS: usize = 10_000;
    if db.len() >= MAX_OBJECTS {
        return Err(Error::Protocol {
            class: ErrorClass::RESOURCES.to_raw() as u32,
            code: ErrorCode::NO_SPACE_FOR_OBJECT.to_raw() as u32,
        });
    }

    let (object_type, instance) = match &request.object_specifier {
        ObjectSpecifier::Type(obj_type) => {
            let existing: HashSet<u32> = db
                .find_by_type(*obj_type)
                .iter()
                .map(|oid| oid.instance_number())
                .collect();
            let next = (1u32..=4_194_303)
                .find(|i| !existing.contains(i))
                .ok_or_else(|| Error::Protocol {
                    class: ErrorClass::RESOURCES.to_raw() as u32,
                    code: ErrorCode::NO_SPACE_FOR_OBJECT.to_raw() as u32,
                })?;
            (*obj_type, next)
        }
        ObjectSpecifier::Identifier(oid) => {
            if db.get(oid).is_some() {
                return Err(Error::Protocol {
                    class: ErrorClass::OBJECT.to_raw() as u32,
                    code: ErrorCode::OBJECT_IDENTIFIER_ALREADY_EXISTS.to_raw() as u32,
                });
            }
            (oid.object_type(), oid.instance_number())
        }
    };

    // Unsupported extensible types need not fit an ObjectIdentifier. Do not
    // truncate them or manufacture an instance when allocation did not occur.
    *target = (object_type.to_raw() <= 1023)
        .then(|| ObjectIdentifier::new(object_type, instance).ok())
        .flatten();
    let name = format!("{:?}-{}", object_type, instance);

    let object: Box<dyn bacnet_objects::traits::BACnetObject> = if object_type
        == ObjectType::ANALOG_INPUT
    {
        Box::new(bacnet_objects::analog::AnalogInputObject::new(
            instance, &name, 95,
        )?)
    } else if object_type == ObjectType::ANALOG_OUTPUT {
        Box::new(bacnet_objects::analog::AnalogOutputObject::new(
            instance, &name, 95,
        )?)
    } else if object_type == ObjectType::BINARY_INPUT {
        Box::new(bacnet_objects::binary::BinaryInputObject::new(
            instance, &name,
        )?)
    } else if object_type == ObjectType::BINARY_OUTPUT {
        Box::new(bacnet_objects::binary::BinaryOutputObject::new(
            instance, &name,
        )?)
    } else if object_type == ObjectType::BINARY_VALUE {
        let mut object = bacnet_objects::binary::BinaryValueObject::new(instance, &name)?;
        // Initial values provision only the optional rows actually requested.
        // Normal WP cannot materialize an absent property. Values still pass
        // the same writer below, including rollback on invalid initialization.
        let mut policy = bacnet_objects::audit::ObjectAuditPolicy::default();
        for value in &request.list_of_initial_values {
            match value.property_identifier {
                PropertyIdentifier::AUDIT_LEVEL => {
                    policy.level = Some(bacnet_types::enums::AuditLevel::DEFAULT)
                }
                PropertyIdentifier::AUDITABLE_OPERATIONS => {
                    policy.operations = Some(bacnet_types::bitstring::AuditOperationFlags::empty())
                }
                PropertyIdentifier::AUDIT_PRIORITY_FILTER => {
                    policy.priority_filter =
                        Some(bacnet_objects::audit::AuditPriorityPolicy::Inherit)
                }
                _ => {}
            }
        }
        object.set_audit_policy(policy);
        Box::new(object)
    } else if object_type == ObjectType::MULTI_STATE_INPUT {
        Box::new(bacnet_objects::multistate::MultiStateInputObject::new(
            instance, &name, 2,
        )?)
    } else if object_type == ObjectType::MULTI_STATE_OUTPUT {
        Box::new(bacnet_objects::multistate::MultiStateOutputObject::new(
            instance, &name, 2,
        )?)
    } else if object_type == ObjectType::MULTI_STATE_VALUE {
        Box::new(bacnet_objects::multistate::MultiStateValueObject::new(
            instance, &name, 2,
        )?)
    } else {
        return Err(Error::Protocol {
            class: ErrorClass::OBJECT.to_raw() as u32,
            code: ErrorCode::UNSUPPORTED_OBJECT_TYPE.to_raw() as u32,
        });
    };

    let created_oid = object.object_identifier();
    *target = Some(created_oid);
    db.add(object)?;
    Ok(created_oid)
}

/// Apply one initial value to the created object. The caller removes the
/// object when this fails.
fn initialize(
    db: &mut ObjectDatabase,
    created_oid: ObjectIdentifier,
    pv: &bacnet_services::common::BACnetPropertyValue,
    command_origin: Option<&bacnet_objects::command_source::CommandOrigin>,
) -> Result<(), CreateObjectRefusal> {
    let decoded = if pv.property_identifier == PropertyIdentifier::VALUE_SOURCE {
        super::write_property::decode_write_property_value(
            pv.property_identifier,
            pv.property_array_index,
            &pv.value,
        )
        .map(|value| (value, pv.value.len()))
    } else {
        bacnet_encoding::primitives::decode_application_value(&pv.value, 0)
    };
    let (value, _) = decoded.map_err(|error| match error {
        Error::Decoding { .. } => CreateObjectRefusal::Malformed(error),
        error => CreateObjectRefusal::Failed(error),
    })?;
    // Route Object_Name initial values through the database name index,
    // matching the WriteProperty handlers: reject a duplicate up front and
    // refresh the index after a successful rename. (The created object was
    // added under its default name, so the index must follow a rename.)
    if pv.property_identifier == PropertyIdentifier::OBJECT_NAME {
        if let PropertyValue::CharacterString(ref new_name) = value {
            db.check_name_available(&created_oid, new_name)
                .map_err(CreateObjectRefusal::Failed)?;
        }
    }
    if let Some(obj) = db.get_mut(&created_oid) {
        crate::command_source::write_target(
            obj,
            pv.property_identifier,
            pv.property_array_index,
            value,
            pv.priority,
            command_origin,
        )
        .map_err(CreateObjectRefusal::Failed)?;
    }
    // A successful Object_Name write changed the object's name field;
    // resync the database name index to the new name.
    if pv.property_identifier == PropertyIdentifier::OBJECT_NAME {
        db.update_name_index(&created_oid);
    }
    Ok(())
}

/// Handle a DeleteObject request.
///
/// Removes the object from the database. Returns an error if the object
/// doesn't exist or is an object type that cannot be deleted at runtime
/// (Device and NetworkPort, which model the running node itself). The set
/// of non-deleteable types is kept in sync with `BACnetObject::is_deleteable`
/// so PICS and runtime dispatch share one truth source.
pub fn handle_delete_object(db: &mut ObjectDatabase, service_data: &[u8]) -> Result<(), Error> {
    let request = DeleteObjectRequest::decode(service_data)?;

    match request.object_identifier.object_type() {
        ObjectType::DEVICE | ObjectType::NETWORK_PORT => {
            return Err(Error::Protocol {
                class: ErrorClass::OBJECT.to_raw() as u32,
                code: ErrorCode::OBJECT_DELETION_NOT_PERMITTED.to_raw() as u32,
            });
        }
        _ => {}
    }

    db.remove(&request.object_identifier)?
        .ok_or(Error::Protocol {
            class: ErrorClass::OBJECT.to_raw() as u32,
            code: ErrorCode::UNKNOWN_OBJECT.to_raw() as u32,
        })?;

    Ok(())
}
