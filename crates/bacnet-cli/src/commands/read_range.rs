//! ReadRange (RR) over a list or log-buffer property.
//!
//! A Trend Log, Event Log, Trend Log Multiple or Audit Log answers a ReadRange
//! of its Log_Buffer with records framed as their Clause 21 productions
//! (Clauses 12.25.14, 12.27.13, 12.30.19 and 12.64.10), not application-tagged
//! values. The record decoder is picked by the object's type, and each record
//! is shown as its timestamp, datum and, for a Trend Log, status flags. Any
//! other property or object type decodes as application values. Whatever
//! doesn't decode is shown as hex.

use bacnet_client::client::BACnetClient;
use bacnet_encoding::constructed::{
    decode_audit_log_record_at, decode_event_log_record, decode_log_multiple_record,
    decode_log_record,
};
use bacnet_transport::port::TransportPort;
use bacnet_types::bitstring::LogStatus;
use bacnet_types::constructed::{
    BACnetAuditLogDatum, BACnetAuditNotification, BACnetRecipient, EventLogDatum,
    EventNotificationRequest, LogData, LogDatum,
};
use bacnet_types::enums::{ErrorClass, ErrorCode, NotifyType, ObjectType, PropertyIdentifier};
use bacnet_types::error::Error;
use bacnet_types::primitives::{Date, ObjectIdentifier, PropertyValue, StatusFlags, Time};
use serde::Serialize;

use super::read::{decode_and_format, format_application_values, hex};
use crate::output::{self, OutputFormat};

/// Read a range of items from a list or log-buffer property.
pub async fn read_range_cmd<T: TransportPort + 'static>(
    client: &BACnetClient<T>,
    mac: &[u8],
    object_type: ObjectType,
    instance: u32,
    property: PropertyIdentifier,
    index: Option<u32>,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let oid = ObjectIdentifier::new(object_type, instance)?;
    let ack = client.read_range(mac, oid, property, index, None).await?;

    let heading = Heading {
        object: format!("{object_type}:{instance}"),
        property: format!("{property}"),
        item_count: ack.item_count,
    };
    let decoder = if property == PropertyIdentifier::LOG_BUFFER {
        record_decoder(object_type)
    } else {
        None
    };
    match decoder {
        Some(decode) => print_records(&heading, &decode_records(decode, &ack.item_data), format),
        None => print_items(&heading, &ack.item_data, format),
    }
    Ok(())
}

/// What every ReadRange output starts with.
struct Heading {
    object: String,
    property: String,
    item_count: u32,
}

/// One log record as the CLI shows it.
#[derive(Debug, PartialEq, Serialize)]
struct LogRecordRow {
    timestamp: String,
    datum: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_flags: Option<String>,
}

/// The records read from a log buffer, and the hex of whatever followed the
/// last record that decoded.
#[derive(Debug, Default)]
struct LogRecords {
    rows: Vec<LogRecordRow>,
    undecoded: Option<String>,
}

/// Decode the record at an offset into its row and the offset just past it.
type RecordDecoder = fn(&[u8], usize) -> Result<(LogRecordRow, usize), Error>;

/// The record decoder for the log buffer of an object of `object_type`, if
/// the type keeps one.
fn record_decoder(object_type: ObjectType) -> Option<RecordDecoder> {
    match object_type {
        ObjectType::TREND_LOG => Some(trend_log_row),
        ObjectType::EVENT_LOG => Some(event_log_row),
        ObjectType::TREND_LOG_MULTIPLE => Some(trend_log_multiple_row),
        ObjectType::AUDIT_LOG => Some(audit_log_row),
        _ => None,
    }
}

/// Decode records until the data runs out or one fails to decode.
fn decode_records(decode: RecordDecoder, data: &[u8]) -> LogRecords {
    let mut records = LogRecords::default();
    let mut offset = 0;
    while offset < data.len() {
        match decode(data, offset) {
            Ok((row, next)) if next > offset => {
                records.rows.push(row);
                offset = next;
            }
            _ => {
                records.undecoded = Some(hex(&data[offset..]));
                break;
            }
        }
    }
    records
}

fn trend_log_row(data: &[u8], offset: usize) -> Result<(LogRecordRow, usize), Error> {
    let (record, next) = decode_log_record(data, offset)?;
    let row = LogRecordRow {
        timestamp: timestamp(record.date, record.time),
        datum: log_datum(&record.log_datum),
        status_flags: record.status_flags.map(status_flags),
    };
    Ok((row, next))
}

fn event_log_row(data: &[u8], offset: usize) -> Result<(LogRecordRow, usize), Error> {
    let (record, next) = decode_event_log_record(data, offset)?;
    let datum = match &record.log_datum {
        EventLogDatum::LogStatus(status) => log_status(*status),
        EventLogDatum::Notification(notification) => event_notification(notification),
        EventLogDatum::TimeChange(seconds) => time_change(*seconds),
    };
    let row = LogRecordRow {
        timestamp: timestamp(record.date, record.time),
        datum,
        status_flags: None,
    };
    Ok((row, next))
}

fn trend_log_multiple_row(data: &[u8], offset: usize) -> Result<(LogRecordRow, usize), Error> {
    let (record, next) = decode_log_multiple_record(data, offset)?;
    let datum = match &record.log_data {
        LogData::LogStatus(status) => log_status(*status),
        LogData::Values(values) => {
            let values: Vec<String> = values
                .iter()
                .map(|value| log_datum(&LogDatum::from(value.clone())))
                .collect();
            format!("[{}]", values.join(", "))
        }
        LogData::TimeChange(seconds) => time_change(*seconds),
    };
    let row = LogRecordRow {
        timestamp: timestamp(record.date, record.time),
        datum,
        status_flags: None,
    };
    Ok((row, next))
}

fn audit_log_row(data: &[u8], offset: usize) -> Result<(LogRecordRow, usize), Error> {
    let (record, next) = decode_audit_log_record_at(data, offset)?;
    let datum = match &record.datum {
        BACnetAuditLogDatum::LogStatus(status) => log_status(*status),
        BACnetAuditLogDatum::AuditNotification(notification) => audit_notification(notification),
        BACnetAuditLogDatum::TimeChange(seconds) => time_change(*seconds),
    };
    let (date, time) = record.timestamp;
    let row = LogRecordRow {
        timestamp: timestamp(date, time),
        datum,
        status_flags: None,
    };
    Ok((row, next))
}

fn timestamp(date: Date, time: Time) -> String {
    format!(
        "{} {}",
        output::format_property_value(&PropertyValue::Date(date)),
        output::format_property_value(&PropertyValue::Time(time))
    )
}

/// The set flags by name; empty when none is set.
fn status_flags(flags: StatusFlags) -> String {
    if flags.is_empty() {
        String::new()
    } else {
        flags.to_string()
    }
}

fn log_status(status: LogStatus) -> String {
    format!("log-status {status}")
}

fn time_change(seconds: f32) -> String {
    format!("time-change {seconds} s")
}

fn object(oid: ObjectIdentifier) -> String {
    format!("{}:{}", oid.object_type(), oid.instance_number())
}

fn log_datum(datum: &LogDatum) -> String {
    match datum {
        LogDatum::LogStatus(status) => log_status(*status),
        LogDatum::BooleanValue(value) => value.to_string(),
        LogDatum::RealValue(value) => value.to_string(),
        LogDatum::EnumValue(value) => format!("enumerated({value})"),
        LogDatum::UnsignedValue(value) => value.to_string(),
        LogDatum::SignedValue(value) => value.to_string(),
        LogDatum::BitstringValue { unused_bits, data } => {
            output::format_property_value(&PropertyValue::BitString {
                unused_bits: *unused_bits,
                data: data.clone(),
            })
        }
        LogDatum::NullValue => "null".to_string(),
        LogDatum::Failure {
            error_class,
            error_code,
        } => format!("failure {}", raw_error(*error_class, *error_code)),
        LogDatum::TimeChange(seconds) => time_change(*seconds),
        LogDatum::AnyValue(bytes) => decode_and_format(bytes),
    }
}

/// An error class and code by name, or by number when one doesn't fit the
/// enumeration.
fn raw_error(class: u32, code: u32) -> String {
    let class = u16::try_from(class).map_or(class.to_string(), |raw| {
        ErrorClass::from_raw(raw).to_string()
    });
    let code =
        u16::try_from(code).map_or(code.to_string(), |raw| ErrorCode::from_raw(raw).to_string());
    format!("{class}/{code}")
}

/// Notify type, event type, event object and transition, then the message.
fn event_notification(notification: &EventNotificationRequest) -> String {
    let transition = if notification.notify_type == NotifyType::ACK_NOTIFICATION {
        notification.to_state.to_string()
    } else {
        format!("{} -> {}", notification.from_state, notification.to_state)
    };
    let mut text = format!(
        "{} {} {} {transition}",
        notification.notify_type,
        notification.event_type,
        object(notification.event_object_identifier)
    );
    if let Some(message) = &notification.message_text {
        text.push_str(&format!(" \"{message}\""));
    }
    text
}

/// Operation and target, the device that asked for it, and any error.
fn audit_notification(notification: &BACnetAuditNotification) -> String {
    let mut text = format!(
        "{} {}",
        notification.operation,
        recipient(&notification.target_device)
    );
    if let Some(target) = notification.target_object {
        text.push_str(&format!(" {}", object(target)));
    }
    if let Some(property) = &notification.target_property {
        text.push_str(&format!(" {}", property.property_identifier));
        if let Some(index) = property.property_array_index {
            text.push_str(&format!("[{index}]"));
        }
    }
    text.push_str(&format!(" by {}", recipient(&notification.source_device)));
    if let Some((class, code)) = notification.result {
        text.push_str(&format!(" failed {class}/{code}"));
    }
    text
}

fn recipient(recipient: &BACnetRecipient) -> String {
    match recipient {
        BACnetRecipient::Device(oid) => object(*oid),
        BACnetRecipient::Address(address) => format!(
            "network {} mac [{}]",
            address.network_number,
            hex(&address.mac_address)
        ),
    }
}

fn print_records(heading: &Heading, records: &LogRecords, format: OutputFormat) {
    match format {
        OutputFormat::Table => {
            println!(
                "ReadRange {}  {}  count={}",
                heading.object, heading.property, heading.item_count
            );
            let flags = records.rows.iter().any(|row| row.status_flags.is_some());
            let mut table = comfy_table::Table::new();
            let mut header = vec!["#", "Timestamp", "Datum"];
            if flags {
                header.push("Status flags");
            }
            table.set_header(header);
            for (number, row) in (1..).zip(&records.rows) {
                let mut cells = vec![number.to_string(), row.timestamp.clone(), row.datum.clone()];
                if flags {
                    cells.push(row.status_flags.clone().unwrap_or_default());
                }
                table.add_row(cells);
            }
            println!("{table}");
            if let Some(hex) = &records.undecoded {
                println!("  [raw] {hex}");
            }
        }
        OutputFormat::Json => {
            let mut json = serde_json::json!({
                "object": heading.object,
                "property": heading.property,
                "item_count": heading.item_count,
                "records": records.rows,
            });
            if let Some(hex) = &records.undecoded {
                json["undecoded"] = serde_json::Value::from(hex.as_str());
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&json).unwrap_or_default()
            );
        }
    }
}

fn print_items(heading: &Heading, data: &[u8], format: OutputFormat) {
    let (mut items, undecoded) = format_application_values(data);
    match format {
        OutputFormat::Table => {
            println!(
                "ReadRange {}  {}  count={}",
                heading.object, heading.property, heading.item_count
            );
            for (number, item) in (1..).zip(&items) {
                println!("  [{number}] {item}");
            }
            if let Some(hex) = undecoded {
                println!("  [raw] {hex}");
            }
        }
        OutputFormat::Json => {
            if let Some(hex) = undecoded {
                items.push(format!("[raw: {hex}]"));
            }
            let json = serde_json::json!({
                "object": heading.object,
                "property": heading.property,
                "item_count": heading.item_count,
                "items": items,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&json).unwrap_or_default()
            );
        }
    }
}

#[cfg(test)]
#[path = "read_range_tests.rs"]
mod tests;
