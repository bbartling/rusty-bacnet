//! An Audit Log's Log_Buffer as ReadRange pages it (#1092).
//!
//! The object answers ReadProperty of Log_Buffer with READ_ACCESS_DENIED,
//! because Clause 12.64.10 opens the buffer to ReadRange and AuditLogQuery
//! only. ReadRange instead reads the retained ring through the object's
//! `AuditLogStorage`, the store AuditLogQuery scans, so both services see the
//! same records. Each item is one bare BACnetAuditLogRecord (Clause 21), and
//! its identity is the record's Unsigned64 sequence number and timestamp, so
//! By Position, By Sequence Number and By Time select through the same code
//! as the Event and Trend logs.

use std::collections::VecDeque;

use super::*;
use bacnet_encoding::constructed::encode_audit_log_record;
use bacnet_types::constructed::BACnetAuditLogRecordResult;

/// The items one ReadRange page draws from.
pub(crate) enum RangeItems<'a> {
    /// One value per item, encoded with the page's value encoder.
    Values(Vec<PropertyValue>),
    /// An Audit Log's retained ring, oldest first. A page encodes only the
    /// records it visits, so a narrow window over a full log stays cheap.
    AuditRecords(&'a VecDeque<BACnetAuditLogRecordResult>),
}

impl RangeItems<'_> {
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Values(items) => items.len(),
            Self::AuditRecords(records) => records.len(),
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
        }
    }
}

/// The resolved Log_Buffer of an object backed by an Audit Log store: its
/// items, and identities when every retained record has a usable one.
pub(super) type AuditLogBuffer<'a> = (RangeItems<'a>, Option<Vec<LogRecordIdentity>>);

/// Resolve `LOG_BUFFER` on an object with an Audit Log store, or `None` to
/// leave the request to the ordinary list path.
///
/// The property exists and is a BACnetLIST, so an array index fails the way
/// the ordinary path fails it on any list (Clause 15.8.1.3.1).
pub(super) fn audit_log_buffer<'a>(
    object: &'a dyn BACnetObject,
    request: &ReadRangeRequest,
) -> Result<Option<AuditLogBuffer<'a>>, Error> {
    if request.property_identifier != PropertyIdentifier::LOG_BUFFER {
        return Ok(None);
    }
    let Some(storage) = object.audit_log_storage_internal() else {
        return Ok(None);
    };
    if request.property_array_index.is_some() {
        return Err(Error::Protocol {
            class: ErrorClass::PROPERTY.to_raw() as u32,
            code: ErrorCode::PROPERTY_IS_NOT_AN_ARRAY.to_raw() as u32,
        });
    }
    let records = storage.retained_records();
    // The store keeps sequence numbers nonzero; a zero one leaves the view
    // unnumbered, which the sequence and time selectors refuse.
    let identities = records
        .iter()
        .map(|result| {
            let (date, time) = result.record.timestamp;
            LogRecordIdentity::new(result.sequence_number, date, time)
        })
        .collect();
    Ok(Some((RangeItems::AuditRecords(records), identities)))
}
