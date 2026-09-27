//! Batch correlation must not add raw encoded payloads to diagnostic output.
use super::{DeviceReadResult, DeviceRpmResult, DeviceWriteRequest};
use std::fmt;

impl fmt::Debug for DeviceWriteRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceWriteRequest")
            .field("device_instance", &self.device_instance)
            .field("object_identifier", &self.object_identifier)
            .field("property_identifier", &self.property_identifier)
            .field("property_array_index", &self.property_array_index)
            .field("property_value_len", &self.property_value.len())
            .field("priority", &self.priority)
            .finish()
    }
}
impl fmt::Debug for DeviceReadResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceReadResult")
            .field("request_index", &self.request_index)
            .field("device_instance", &self.device_instance)
            .field(
                "result",
                &self.result.as_ref().map(|_| "ACK payload omitted"),
            )
            .finish()
    }
}
impl fmt::Debug for DeviceRpmResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceRpmResult")
            .field("request_index", &self.request_index)
            .field("device_instance", &self.device_instance)
            .field(
                "result",
                &self.result.as_ref().map(|_| "ACK payload omitted"),
            )
            .finish()
    }
}
