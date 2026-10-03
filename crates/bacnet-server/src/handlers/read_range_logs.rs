//! A log object's Log_Buffer as ReadRange pages it (#1092, #1237).
//!
//! Every built-in log answers ReadProperty of Log_Buffer with
//! READ_ACCESS_DENIED: Clauses 12.25.14, 12.27.13, 12.30.19 and 12.64.10 open
//! the buffer to ReadRange (and, for an Audit Log, AuditLogQuery) only.
//! ReadRange reads the records straight from the object instead. An Audit
//! Log's come from its `AuditLogStorage`, the store AuditLogQuery scans, so
//! both services see the same records, each item one bare
//! BACnetAuditLogRecord whose identity is its Unsigned64 sequence number and
//! timestamp. A Trend Log, Event Log or Trend Log Multiple lends its record
//! buffer through `log_buffer_internal`, each item one record framed as its
//! Clause 21 production (#1233), with the object's resident identities. By
//! Position, By Sequence Number and By Time then select through the same
//! code for every log.

use std::collections::VecDeque;

use super::*;
use bacnet_encoding::constructed::encode_audit_log_record;
use bacnet_objects::log_buffer::LogBufferRecords;
use bacnet_types::constructed::BACnetAuditLogRecordResult;

/// The items one ReadRange page draws from.
pub(crate) enum RangeItems<'a> {
    /// One value per item, encoded with the page's value encoder.
    Values(Vec<PropertyValue>),
    /// An Audit Log's retained ring, oldest first. A page encodes only the
    /// records it visits, so a narrow window over a full log stays cheap.
    AuditRecords(&'a VecDeque<BACnetAuditLogRecordResult>),
    /// A Trend Log, Event Log or Trend Log Multiple buffer, oldest first,
    /// likewise encoded only where a page visits it.
    LogRecords(&'a dyn LogBufferRecords),
}

impl RangeItems<'_> {
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Values(items) => items.len(),
            Self::AuditRecords(records) => records.len(),
            Self::LogRecords(records) => records.record_count(),
        }
    }

    /// Encode item `index`, handing values to `encode_value`.
    pub(super) fn encode_with<F>(
        &self,
        index: usize,
        buf: &mut BytesMut,
        encode_value: &mut F,
    ) -> Result<(), Error>
    where
        F: FnMut(&mut BytesMut, &PropertyValue) -> Result<(), Error>,
    {
        match self {
            Self::Values(items) => encode_value(buf, &items[index]),
            Self::AuditRecords(records) => encode_audit_log_record(&records[index].record, buf),
            Self::LogRecords(records) => records.encode_record(index, buf),
        }
    }
}

/// The resolved Log_Buffer of a log object: its items, and identities when
/// every retained record has a usable one.
pub(super) type LogBuffer<'a> = (RangeItems<'a>, Option<Vec<LogRecordIdentity>>);

/// Resolve `LOG_BUFFER` on an object that serves it outside ReadProperty (an
/// Audit Log store or a log record buffer), or `None` to leave the request to
/// the ordinary list path.
///
/// The property exists and is a BACnetLIST, so an array index fails the way
/// the ordinary path fails it on any list (Clause 15.8.1.3.1).
pub(super) fn log_buffer<'a>(
    object: &'a dyn BACnetObject,
    request: &ReadRangeRequest,
) -> Result<Option<LogBuffer<'a>>, Error> {
    if request.property_identifier != PropertyIdentifier::LOG_BUFFER {
        return Ok(None);
    }
    let resolved = if let Some(storage) = object.audit_log_storage_internal() {
        let records = storage.retained_records();
        // The store keeps sequence numbers nonzero; a zero one leaves the
        // view unnumbered, which the sequence and time selectors refuse.
        let identities = records
            .iter()
            .map(|result| {
                let (date, time) = result.record.timestamp;
                LogRecordIdentity::new(result.sequence_number, date, time)
            })
            .collect();
        (RangeItems::AuditRecords(records), identities)
    } else if let Some(records) = object.log_buffer_internal() {
        (
            RangeItems::LogRecords(records),
            object.log_record_identities_internal(),
        )
    } else {
        return Ok(None);
    };
    if request.property_array_index.is_some() {
        return Err(Error::Protocol {
            class: ErrorClass::PROPERTY.to_raw() as u32,
            code: ErrorCode::PROPERTY_IS_NOT_AN_ARRAY.to_raw() as u32,
        });
    }
    Ok(Some(resolved))
}
