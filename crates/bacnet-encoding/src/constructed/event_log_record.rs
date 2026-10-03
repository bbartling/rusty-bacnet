//! Event Log log records (Clause 12.27.13), framed as Clause 21 gives
//! BACnetEventLogRecord.
//!
//! A record is two constructed fields. Context tag 0 wraps the timestamp, an
//! application Date then an application Time. Context tag 1 wraps the log
//! datum, one of three alternatives: a primitive context 0 holding the
//! three-bit log status, a constructed context 1 holding a notification's
//! request parameters, or a primitive context 2 holding the clock change as
//! a REAL.

use super::log_fields::{
    constructed, decode_log_status, decode_timestamp, encode_log_status, encode_timestamp,
    primitive,
};
use super::validate_tlv_sequence;
use crate::{primitives, tags};
use bacnet_types::constructed::{BACnetEventLogRecord, EventLogDatum};
use bacnet_types::error::Error;
use bytes::BytesMut;

const RECORD: &str = "BACnetEventLogRecord";

const LOG_STATUS: u8 = 0;
const NOTIFICATION: u8 = 1;
const TIME_CHANGE: u8 = 2;

/// Encode one Event Log record.
///
/// Fails, leaving `buf` unchanged, for notification bytes that aren't a
/// well-formed run of tagged fields.
pub fn encode_event_log_record(
    record: &BACnetEventLogRecord,
    buf: &mut BytesMut,
) -> Result<(), Error> {
    let mut out = BytesMut::new();
    encode_timestamp(&mut out, &record.date, &record.time);
    tags::encode_opening_tag(&mut out, 1);
    match &record.log_datum {
        EventLogDatum::LogStatus(status) => encode_log_status(&mut out, LOG_STATUS, *status),
        EventLogDatum::Notification(parameters) => {
            validate_tlv_sequence(parameters, "BACnetEventLogRecord notification")
                .map_err(|error| Error::Encoding(error.to_string()))?;
            tags::encode_opening_tag(&mut out, NOTIFICATION);
            out.extend_from_slice(parameters);
            tags::encode_closing_tag(&mut out, NOTIFICATION);
        }
        EventLogDatum::TimeChange(seconds) => {
            primitives::encode_ctx_real(&mut out, TIME_CHANGE, *seconds)
        }
    }
    tags::encode_closing_tag(&mut out, 1);
    buf.extend_from_slice(&out);
    Ok(())
}

/// Decode one Event Log record starting at `offset`, returning it and the
/// offset just past it.
///
/// A notification is checked only as a well-formed run of tagged fields;
/// `bacnet_services`' `EventNotificationRequest::decode` parses it.
pub fn decode_event_log_record(
    data: &[u8],
    offset: usize,
) -> Result<(BACnetEventLogRecord, usize), Error> {
    let (date, time, datum_start) = decode_timestamp(data, offset, RECORD)?;
    let (body, end) = constructed(data, datum_start, 1, RECORD, "log-datum")?;
    let log_datum = decode_datum(body, datum_start)?;
    Ok((
        BACnetEventLogRecord {
            date,
            time,
            log_datum,
        },
        end,
    ))
}

fn decode_datum(data: &[u8], offset: usize) -> Result<EventLogDatum, Error> {
    let (tag, start) = tags::decode_tag(data, 0)?;
    let (datum, end) = if tag.is_context(LOG_STATUS) {
        let (contents, end) = primitive(data, tag, start)?;
        let status = decode_log_status(contents, offset, RECORD)?;
        (EventLogDatum::LogStatus(status), end)
    } else if tag.is_opening_tag(NOTIFICATION) {
        let (parameters, end) = tags::extract_context_value(data, start, NOTIFICATION)?;
        validate_tlv_sequence(parameters, "BACnetEventLogRecord notification")?;
        (EventLogDatum::Notification(parameters.to_vec()), end)
    } else if tag.is_context(TIME_CHANGE) {
        let (contents, end) = primitive(data, tag, start)?;
        (
            EventLogDatum::TimeChange(primitives::decode_real(contents)?),
            end,
        )
    } else {
        return Err(Error::decoding(
            offset,
            "BACnetEventLogRecord log-datum expected context [0], constructed [1], or context [2]",
        ));
    };
    if end != data.len() {
        return Err(Error::decoding(
            offset,
            "BACnetEventLogRecord log-datum has trailing fields",
        ));
    }
    Ok(datum)
}
