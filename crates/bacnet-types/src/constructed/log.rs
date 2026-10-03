//! Log buffer records of three log objects: Trend Log (Clause 12.25.14),
//! Event Log (Clause 12.27.13) and Trend Log Multiple (Clause 12.30.19). The
//! record productions are in Clause 21; the encoding crate frames each one
//! on the wire.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::primitives::{Date, Time};

// ---------------------------------------------------------------------------
// LogDatum (Clause 12.25.14 -- Trend Log Log_Buffer)
// ---------------------------------------------------------------------------

/// What a Trend Log record carries: a sampled value, the error that stopped
/// the sample, a status change of the log, or a clock change.
///
/// On the wire each alternative takes a context tag, 0 to 10 in declaration
/// order; the encoding crate owns that numbering.
#[derive(Debug, Clone, PartialEq)]
pub enum LogDatum {
    /// A status change of the log itself: BACnetLogStatus flags, bit 0
    /// log-disabled, bit 1 buffer-purged, bit 2 log-interrupted.
    LogStatus(u8),
    /// A BOOLEAN value.
    BooleanValue(bool),
    /// A REAL value.
    RealValue(f32),
    /// An ENUMERATED value.
    EnumValue(u32),
    /// An Unsigned value.
    UnsignedValue(u64),
    /// An INTEGER value.
    SignedValue(i32),
    /// A BIT STRING value.
    BitstringValue {
        /// Padding bits at the end of the final octet, 0 to 7.
        unused_bits: u8,
        /// The bit data.
        data: Vec<u8>,
    },
    /// A NULL value.
    NullValue,
    /// The error that kept the value from being logged.
    Failure {
        /// Raw BACnet error class value.
        error_class: u32,
        /// Raw BACnet error code value.
        error_code: u32,
    },
    /// The device clock moved by this many seconds; zero when unknown.
    TimeChange(f32),
    /// A value of any other datatype, as the tagged encoding a property read
    /// carries for it: one or more complete values, context tags balanced.
    AnyValue(Vec<u8>),
}

impl From<LogValue> for LogDatum {
    /// The same sampled value as a Trend Log datum.
    fn from(value: LogValue) -> Self {
        match value {
            LogValue::BooleanValue(value) => Self::BooleanValue(value),
            LogValue::RealValue(value) => Self::RealValue(value),
            LogValue::EnumValue(value) => Self::EnumValue(value),
            LogValue::UnsignedValue(value) => Self::UnsignedValue(value),
            LogValue::SignedValue(value) => Self::SignedValue(value),
            LogValue::BitstringValue { unused_bits, data } => {
                Self::BitstringValue { unused_bits, data }
            }
            LogValue::NullValue => Self::NullValue,
            LogValue::Failure {
                error_class,
                error_code,
            } => Self::Failure {
                error_class,
                error_code,
            },
            LogValue::AnyValue(bytes) => Self::AnyValue(bytes),
        }
    }
}

// ---------------------------------------------------------------------------
// BACnetLogRecord (Clause 12.25.14 -- Trend Log Log_Buffer)
// ---------------------------------------------------------------------------

/// One record held in the log buffer of a Trend Log (Clause 12.25.14).
///
/// Contains a timestamp (date + time), the logged datum, and optional
/// status flags that were in effect at logging time.
#[derive(Debug, Clone, PartialEq)]
pub struct BACnetLogRecord {
    /// The date at which this record was logged.
    pub date: Date,
    /// The time at which this record was logged.
    pub time: Time,
    /// The logged datum.
    pub log_datum: LogDatum,
    /// The monitored object's Status_Flags when the value was acquired, if
    /// recorded: bit 0 in-alarm, bit 1 fault, bit 2 overridden, bit 3
    /// out-of-service.
    pub status_flags: Option<u8>,
}

// ---------------------------------------------------------------------------
// BACnetEventLogRecord (Clause 12.27.13 -- Event Log Log_Buffer)
// ---------------------------------------------------------------------------

/// What an Event Log record carries.
///
/// On the wire the alternatives take context tags 0 to 2 in declaration
/// order; the encoding crate owns that numbering.
#[derive(Debug, Clone, PartialEq)]
pub enum EventLogDatum {
    /// A status change of the log itself: BACnetLogStatus flags, bit 0
    /// log-disabled, bit 1 buffer-purged, bit 2 log-interrupted.
    LogStatus(u8),
    /// An event notification, as the encoded parameters of a
    /// ConfirmedEventNotification request: its tagged fields from the process
    /// identifier through the optional event values, with no frame around
    /// them. `bacnet_services`' `EventNotificationRequest` encodes and
    /// decodes these bytes.
    Notification(Vec<u8>),
    /// The device clock moved by this many seconds; zero when unknown.
    TimeChange(f32),
}

/// One record held in the log buffer of an Event Log (Clause 12.27.13).
#[derive(Debug, Clone, PartialEq)]
pub struct BACnetEventLogRecord {
    /// The local date at which the record was placed in the buffer.
    pub date: Date,
    /// The local time at which the record was placed in the buffer.
    pub time: Time,
    /// The record's contents.
    pub log_datum: EventLogDatum,
}

// ---------------------------------------------------------------------------
// BACnetLogMultipleRecord (Clause 12.30.19 -- Trend Log Multiple Log_Buffer)
// ---------------------------------------------------------------------------

/// One sampled value, or the error that stopped the sample, in a Trend Log
/// Multiple record (Clause 12.30.19).
///
/// These are the per-member alternatives of Clause 21's BACnetLogData. On the
/// wire they take context tags 0 to 8 in declaration order; the encoding crate
/// owns that numbering, which differs from [`LogDatum`]'s.
#[derive(Debug, Clone, PartialEq)]
pub enum LogValue {
    /// A BOOLEAN value.
    BooleanValue(bool),
    /// A REAL value.
    RealValue(f32),
    /// An ENUMERATED value.
    EnumValue(u32),
    /// An Unsigned value.
    UnsignedValue(u64),
    /// An INTEGER value.
    SignedValue(i32),
    /// A BIT STRING value.
    BitstringValue {
        /// Padding bits at the end of the final octet, 0 to 7.
        unused_bits: u8,
        /// The bit data.
        data: Vec<u8>,
    },
    /// A NULL value.
    NullValue,
    /// The error that kept this member from being logged.
    Failure {
        /// Raw BACnet error class value.
        error_class: u32,
        /// Raw BACnet error code value.
        error_code: u32,
    },
    /// A value of any other datatype, as the tagged encoding a property read
    /// carries for it: one or more complete values, context tags balanced.
    AnyValue(Vec<u8>),
}

/// What a Trend Log Multiple record carries (Clause 21's BACnetLogData).
#[derive(Debug, Clone, PartialEq)]
pub enum LogData {
    /// A status change of the log itself: BACnetLogStatus flags, bit 0
    /// log-disabled, bit 1 buffer-purged, bit 2 log-interrupted.
    LogStatus(u8),
    /// One entry per Log_DeviceObjectProperty member, in member order.
    Values(Vec<LogValue>),
    /// The device clock moved by this many seconds; zero when unknown.
    TimeChange(f32),
}

/// One record held in the log buffer of a Trend Log Multiple
/// (Clause 12.30.19).
#[derive(Debug, Clone, PartialEq)]
pub struct BACnetLogMultipleRecord {
    /// The local date at which the record was acquired.
    pub date: Date,
    /// The local time at which the record was acquired.
    pub time: Time,
    /// The record's contents.
    pub log_data: LogData,
}
