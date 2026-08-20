//! Audit notification and query wire models.
//!
//! These codecs follow the formal Clause 21 productions in ASHRAE 135-2020.
//! Clause 13.19 conflicts with them by describing an `Unsigned64` start
//! sequence and a three-state success filter. This model intentionally uses
//! Clause 21's `Unsigned32` and strict mandatory Boolean forms.

use bacnet_types::bitstring::AuditOperationFlags;
use bacnet_types::constructed::{BACnetAddress, BACnetRecipient};
use bacnet_types::enums::{AuditOperation, ErrorClass, ErrorCode, PropertyIdentifier};
use bacnet_types::error::Error;
use bacnet_types::primitives::{BACnetTimeStamp, ObjectIdentifier};
use bytes::BytesMut;

use crate::common::PropertyReference;

#[path = "audit/notification_codec.rs"]
mod notification_codec;
#[path = "audit/query_codec.rs"]
mod query_codec;

/// Parameters shared by confirmed and unconfirmed AuditNotification.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditNotificationRequest {
    /// One or more notifications, encoded under context tag `[0]`.
    pub notifications: Vec<BACnetAuditNotification>,
}

/// One audit operation record (`BACnetAuditNotification`, Clause 21).
#[derive(Debug, Clone, PartialEq)]
pub struct BACnetAuditNotification {
    pub source_timestamp: Option<BACnetTimeStamp>,
    pub target_timestamp: Option<BACnetTimeStamp>,
    pub source_device: BACnetRecipient,
    pub source_object: Option<ObjectIdentifier>,
    pub operation: AuditOperation,
    pub source_comment: Option<String>,
    pub target_comment: Option<String>,
    pub invoke_id: Option<u8>,
    pub source_user_id: Option<u16>,
    pub source_user_role: Option<u8>,
    pub target_device: BACnetRecipient,
    pub target_object: Option<ObjectIdentifier>,
    pub target_property: Option<PropertyReference>,
    /// Command priority, constrained to `1..=16` when present.
    pub target_priority: Option<u8>,
    /// Raw, structurally validated `ABSTRACT-SYNTAX.&Type` encoding.
    pub target_value: Option<Vec<u8>>,
    /// Raw, structurally validated `ABSTRACT-SYNTAX.&Type` encoding.
    pub current_value: Option<Vec<u8>>,
    pub result: Option<(ErrorClass, ErrorCode)>,
}

/// Typed `BACnetAuditLogQueryParameters` CHOICE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BACnetAuditLogQueryParameters {
    ByTarget {
        target_device_identifier: ObjectIdentifier,
        target_device_address: Option<BACnetAddress>,
        target_object_identifier: Option<ObjectIdentifier>,
        target_property_identifier: Option<PropertyIdentifier>,
        target_array_index: Option<u32>,
        /// Command priority filter, constrained to `1..=16` when present.
        target_priority: Option<u8>,
        operations: Option<AuditOperationFlags>,
        successful_actions_only: bool,
    },
    BySource {
        source_device_identifier: ObjectIdentifier,
        source_device_address: Option<BACnetAddress>,
        source_object_identifier: Option<ObjectIdentifier>,
        operations: Option<AuditOperationFlags>,
        successful_actions_only: bool,
    },
}

/// AuditLogQuery-Request service parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLogQueryRequest {
    pub audit_log: ObjectIdentifier,
    pub query_parameters: BACnetAuditLogQueryParameters,
    /// Clause 21 constrains this field to `Unsigned32`.
    pub start_at_sequence_number: Option<u32>,
    pub requested_count: u16,
}

fn decode_canonical_unsigned(data: &[u8], offset: usize, field: &str) -> Result<u64, Error> {
    if data.len() > 1 && data.first() == Some(&0) {
        return Err(Error::decoding(
            offset,
            format!("{field} must use the shortest Unsigned/Enumerated encoding"),
        ));
    }
    bacnet_encoding::primitives::decode_unsigned(data)
}

impl AuditNotificationRequest {
    /// Encode after validation, leaving `buf` unchanged on failure.
    pub fn try_encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        notification_codec::encode(self, buf)
    }

    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        self.try_encode(buf)
    }

    /// Decode a complete payload; trailing bytes are rejected.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        notification_codec::decode(data)
    }
}

impl AuditLogQueryRequest {
    /// Encode after validation, leaving `buf` unchanged on failure.
    pub fn try_encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        query_codec::encode(self, buf)
    }

    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        self.try_encode(buf)
    }

    /// Decode a complete payload; trailing bytes are rejected.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        query_codec::decode(data)
    }
}

#[cfg(test)]
#[path = "audit/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "audit/malformed_tests.rs"]
mod malformed_tests;
