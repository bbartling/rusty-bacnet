//! Executor-owned Device reads, independent of mutable object declarations.
//! This request-scoped adapter never changes the database or service dispatch.
use crate::cov::active::LiveDeviceCov;
use bacnet_objects::{
    database::ObjectDatabase,
    device::EXECUTED_SERVICES,
    property_metadata::{PropertyConformance, PropertyMetadata, PropertyWriteCapability},
    traits::BACnetObject,
};
use bacnet_types::{
    enums::{ErrorClass, ErrorCode, ObjectType, PropertyIdentifier as P, ServiceSupported},
    error::Error,
    primitives::{ObjectIdentifier, PropertyValue},
};
use std::borrow::Cow;

#[derive(Clone, Copy)]
pub(crate) enum DeviceExecution {
    FullServer,
    Endpoint { writes: bool },
}

impl DeviceExecution {
    pub(crate) fn services(self, clock: bool) -> impl Iterator<Item = ServiceSupported> {
        let services: &[ServiceSupported] = match self {
            Self::FullServer => EXECUTED_SERVICES,
            Self::Endpoint { writes: false } => &[ServiceSupported::READ_PROPERTY],
            Self::Endpoint { writes: true } => &[
                ServiceSupported::READ_PROPERTY,
                ServiceSupported::WRITE_PROPERTY,
            ],
        };
        services.iter().copied().filter(move |service| {
            clock
                || !matches!(
                    *service,
                    ServiceSupported::TIME_SYNCHRONIZATION
                        | ServiceSupported::UTC_TIME_SYNCHRONIZATION
                )
        })
    }
}

/// One execution profile and clock observation, shared across a served request.
pub(crate) struct DeviceReadContext<'a> {
    pub(crate) registered_port: Option<ObjectIdentifier>,
    execution: DeviceExecution,
    clock: bool,
    live: Option<&'a LiveDeviceCov>,
}

impl<'a> DeviceReadContext<'a> {
    pub(crate) fn new(
        db: &ObjectDatabase,
        execution: DeviceExecution,
        live: Option<&'a LiveDeviceCov>,
    ) -> Self {
        Self {
            registered_port: None,
            execution,
            clock: db.clock_frame().is_some(),
            live,
        }
    }
    pub(crate) fn with_registered_port(mut self, oid: Option<ObjectIdentifier>) -> Self {
        self.registered_port = oid;
        self
    }
    pub(crate) fn object<'b>(&'b self, object: &'b dyn BACnetObject) -> DeviceReadView<'b> {
        DeviceReadView {
            object,
            context: self,
        }
    }
}

pub(crate) struct DeviceReadView<'a> {
    object: &'a dyn BACnetObject,
    context: &'a DeviceReadContext<'a>,
}

fn owned(property: P) -> bool {
    matches!(
        property,
        P::PROTOCOL_SERVICES_SUPPORTED
            | P::PROPERTY_LIST
            | P::ACTIVE_COV_SUBSCRIPTIONS
            | P::ACTIVE_COV_MULTIPLE_SUBSCRIPTIONS
    )
}
/// The four served fields cannot be assigned through a custom Device writer.
/// Call only after the existing object/index/value and authorization preflight.
pub(crate) fn check_executor_owned_write(oid: ObjectIdentifier, property: P) -> Result<(), Error> {
    if oid.object_type() == ObjectType::DEVICE && owned(property) {
        Err(property_error(ErrorCode::WRITE_ACCESS_DENIED))
    } else {
        Ok(())
    }
}

fn property_error(code: ErrorCode) -> Error {
    Error::Protocol {
        class: ErrorClass::PROPERTY.to_raw() as u32,
        code: code.to_raw() as u32,
    }
}

impl DeviceReadView<'_> {
    fn is_device(&self) -> bool {
        self.object.object_identifier().object_type() == ObjectType::DEVICE
    }
    fn cov_present(&self) -> bool {
        matches!(self.context.execution, DeviceExecution::FullServer)
    }
}

impl BACnetObject for DeviceReadView<'_> {
    fn object_identifier(&self) -> ObjectIdentifier {
        self.object.object_identifier()
    }
    fn object_name(&self) -> &str {
        self.object.object_name()
    }
    fn read_property(&self, property: P, index: Option<u32>) -> Result<PropertyValue, Error> {
        if !self.is_device() || !owned(property) {
            return self.object.read_property(property, index);
        }
        if index.is_some() && !self.is_array_property(property) {
            return Err(property_error(ErrorCode::PROPERTY_IS_NOT_AN_ARRAY));
        }
        match property {
            P::PROPERTY_LIST => {
                let properties: Vec<_> = self
                    .property_list()
                    .iter()
                    .copied()
                    .filter(|property| {
                        !matches!(
                            *property,
                            P::OBJECT_IDENTIFIER
                                | P::OBJECT_NAME
                                | P::OBJECT_TYPE
                                | P::PROPERTY_LIST
                        )
                    })
                    .collect();
                match index {
                    None => Ok(PropertyValue::List(
                        properties
                            .iter()
                            .map(|property| PropertyValue::Enumerated(property.to_raw()))
                            .collect(),
                    )),
                    Some(0) => Ok(PropertyValue::Unsigned(properties.len() as u64)),
                    Some(index) => properties
                        .get((index - 1) as usize)
                        .map(|property| PropertyValue::Enumerated(property.to_raw()))
                        .ok_or_else(|| property_error(ErrorCode::INVALID_ARRAY_INDEX)),
                }
            }
            P::PROTOCOL_SERVICES_SUPPORTED => {
                // Clause 21 BACnetServicesSupported: 49 defined bits, MSB first.
                let mut data = vec![0; 7];
                for service in self.context.execution.services(self.context.clock) {
                    let bit = usize::from(service.to_raw());
                    data[bit / 8] |= 0x80 >> (bit % 8);
                }
                Ok(PropertyValue::BitString {
                    unused_bits: 7,
                    data,
                })
            }
            _ if self.cov_present() => Ok(self
                .context
                .live
                .and_then(|live| live.resolve(self.object_identifier(), property))
                .unwrap_or_else(|| PropertyValue::ApplicationData(Vec::new()))),
            _ => Err(property_error(ErrorCode::UNKNOWN_PROPERTY)),
        }
    }
    fn write_property(
        &mut self,
        _: P,
        _: Option<u32>,
        _: PropertyValue,
        _: Option<u8>,
    ) -> Result<(), Error> {
        Err(property_error(ErrorCode::WRITE_ACCESS_DENIED))
    }
    fn property_metadata(&self) -> Cow<'_, [PropertyMetadata]> {
        if !self.is_device() {
            return self.object.property_metadata();
        }
        let original = self.object.property_metadata();
        let mut rows: Vec<_> = if original.is_empty() {
            let required = self.object.required_properties();
            self.object
                .property_list()
                .iter()
                .copied()
                .map(|property| {
                    PropertyMetadata::new(
                        property,
                        if required.contains(&property) {
                            PropertyConformance::RequiredRead
                        } else {
                            PropertyConformance::Optional
                        },
                        None,
                        if self.object.is_writable_property(property) {
                            PropertyWriteCapability::Always
                        } else {
                            PropertyWriteCapability::ReadOnly
                        },
                    )
                })
                .collect()
        } else {
            original.into_owned()
        };
        rows.retain(|row| !owned(row.property_identifier));
        for property in [P::PROTOCOL_SERVICES_SUPPORTED, P::PROPERTY_LIST] {
            rows.push(PropertyMetadata::new(
                property,
                PropertyConformance::RequiredRead,
                None,
                PropertyWriteCapability::ReadOnly,
            ));
        }
        if self.cov_present() {
            for property in [
                P::ACTIVE_COV_SUBSCRIPTIONS,
                P::ACTIVE_COV_MULTIPLE_SUBSCRIPTIONS,
            ] {
                rows.push(PropertyMetadata::new(
                    property,
                    PropertyConformance::Optional,
                    None,
                    PropertyWriteCapability::ReadOnly,
                ));
            }
        }
        rows.sort_by_key(|row| row.property_identifier.to_raw());
        Cow::Owned(rows)
    }
    fn property_list(&self) -> Cow<'static, [P]> {
        if !self.is_device() {
            return self.object.property_list();
        }
        Cow::Owned(
            self.property_metadata()
                .iter()
                .map(|row| row.property_identifier)
                .collect(),
        )
    }
    fn required_properties(&self) -> Cow<'static, [P]> {
        if !self.is_device() {
            return self.object.required_properties();
        }
        bacnet_objects::property_metadata::required_properties_from_metadata(
            &self.property_metadata(),
        )
    }
    fn is_array_property(&self, property: P) -> bool {
        if self.is_device() && owned(property) {
            property == P::PROPERTY_LIST
        } else {
            self.object.is_array_property(property)
        }
    }
    /// ReadRange asks this of the served object (#1046): the two COV lists
    /// are BACnetLISTs, Property_List is an array and the services bit
    /// string is a single value.
    fn is_list_property(&self, property: P) -> bool {
        if self.is_device() && owned(property) {
            matches!(
                property,
                P::ACTIVE_COV_SUBSCRIPTIONS | P::ACTIVE_COV_MULTIPLE_SUBSCRIPTIONS
            )
        } else {
            self.object.is_list_property(property)
        }
    }
    fn is_writable_property(&self, property: P) -> bool {
        if self.is_device() && owned(property) {
            false
        } else {
            self.object.is_writable_property(property)
        }
    }
    fn log_record_identities_internal(
        &self,
    ) -> Option<Vec<bacnet_objects::log_buffer::LogRecordIdentity>> {
        self.object.log_record_identities_internal()
    }
}
