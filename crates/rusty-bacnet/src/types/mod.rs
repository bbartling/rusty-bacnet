//! Python-facing type wrappers for BACnet enums, ObjectIdentifier, and PropertyValue.

#![allow(non_snake_case)]

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use bytes::BytesMut;
use pyo3::exceptions::{PyStopAsyncIteration, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use pyo3::Py;
use tokio::sync::broadcast;

use bacnet_client::client::{COVNotificationDelivery, ReceivedCOVNotification};
use bacnet_client::discovery::DiscoveredDevice;
use bacnet_encoding::primitives::encode_property_value;
use bacnet_services::common::BACnetPropertyValue;
use bacnet_services::rpm::ReadPropertyMultipleACK;
use bacnet_services::wpm::WriteAccessSpecification;
use bacnet_types::constructed::{PropertyReference, ReadAccessSpecification};
use bacnet_types::enums as bacnet_enums;
use bacnet_types::primitives;

mod access_rule;
mod action_list;
mod address;
mod audit;
mod audit_projection;
mod constructed_py;
mod constructed_read;
mod cov;
mod destination;
mod device;
mod enums;
mod mapping;
mod object_identifier;
mod property_reference;
mod property_value;
mod read_value;
mod rpm_wpm;
mod timestamp;

pub(crate) use access_rule::{access_rules_from_py, device_object_reference};
pub(crate) use action_list::action_lists_from_py;
pub use address::parse_address;
pub(crate) use audit::recipient as audit_recipient_from_py;
pub(crate) use audit::{audit_log_query_request_from_py, audit_notification_request_from_py};
pub(crate) use audit_projection::audit_log_query_ack_to_py;
pub use cov::{PyCovNotification, PyCovNotificationIterator};
pub(crate) use destination::destination as destination_from_py;
pub use device::PyDiscoveredDevice;
pub use enums::*;
pub use object_identifier::PyObjectIdentifier;
pub(crate) use property_reference::{
    check_device, local_device, localize, property_references_from_py,
};
pub use property_value::PyPropertyValue;
pub(crate) use read_value::{decode_read_ack, decode_read_value};
pub(crate) use rpm_wpm::{
    py_to_rpm_specs, py_to_wpm_specs, rpm_ack_to_py, PyDeviceWrite, PyPropertyWrite,
    PyReadAccessSpec, PyWriteAccessSpec,
};
pub(crate) use timestamp::date_time_tuple;
pub use timestamp::PyBACnetTimeStamp;

// Module registration
// ---------------------------------------------------------------------------

/// Register all type classes with the module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Enum types — add class then populate constants from ALL_NAMED.
    m.add_class::<PyObjectType>()?;
    PyObjectType::register_constants(&m.getattr("ObjectType")?)?;

    m.add_class::<PyPropertyIdentifier>()?;
    PyPropertyIdentifier::register_constants(&m.getattr("PropertyIdentifier")?)?;

    m.add_class::<PyErrorClass>()?;
    PyErrorClass::register_constants(&m.getattr("ErrorClass")?)?;

    m.add_class::<PyErrorCode>()?;
    PyErrorCode::register_constants(&m.getattr("ErrorCode")?)?;

    m.add_class::<PyAuditOperation>()?;
    PyAuditOperation::register_constants(&m.getattr("AuditOperation")?)?;

    m.add_class::<PyEnableDisable>()?;
    PyEnableDisable::register_constants(&m.getattr("EnableDisable")?)?;

    m.add_class::<PyReinitializedState>()?;
    PyReinitializedState::register_constants(&m.getattr("ReinitializedState")?)?;

    m.add_class::<PySegmentation>()?;
    PySegmentation::register_constants(&m.getattr("Segmentation")?)?;

    m.add_class::<PyLifeSafetyOperation>()?;
    PyLifeSafetyOperation::register_constants(&m.getattr("LifeSafetyOperation")?)?;

    m.add_class::<PyEventState>()?;
    PyEventState::register_constants(&m.getattr("EventState")?)?;

    m.add_class::<PyAcknowledgmentFilter>()?;
    PyAcknowledgmentFilter::register_constants(&m.getattr("AcknowledgmentFilter")?)?;

    m.add_class::<PyEnrollmentSummaryEventStateFilter>()?;
    PyEnrollmentSummaryEventStateFilter::register_constants(
        &m.getattr("EnrollmentSummaryEventStateFilter")?,
    )?;

    m.add_class::<PyEventType>()?;
    PyEventType::register_constants(&m.getattr("EventType")?)?;

    m.add_class::<PyMessagePriority>()?;
    PyMessagePriority::register_constants(&m.getattr("MessagePriority")?)?;

    m.add_class::<PyVTClass>()?;
    PyVTClass::register_constants(&m.getattr("VTClass")?)?;

    // Composite types
    m.add_class::<PyObjectIdentifier>()?;
    m.add_class::<PyPropertyValue>()?;
    m.add_class::<PyBACnetTimeStamp>()?;
    m.add_class::<PyDiscoveredDevice>()?;
    m.add_class::<PyCovNotification>()?;
    m.add_class::<PyCovNotificationIterator>()?;

    Ok(())
}

#[cfg(test)]
mod tests;
