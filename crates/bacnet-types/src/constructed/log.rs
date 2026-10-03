//! Log buffer records of the Trend Log and Trend Log Multiple objects
//! (Clauses 12.25 and 12.30; the record productions are in Clause 21).

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::primitives::{Date, Time};

// ---------------------------------------------------------------------------
// LogDatum (Clause 12.25 -- TrendLog Log_Buffer; Clause 21.6)
// ---------------------------------------------------------------------------

/// The datum field of a BACnetLogRecord: a CHOICE covering all possible
/// logged value types.
///
/// Context tags per spec:
/// - `[0]` log-status (BACnetLogStatus, 8-bit flags)
/// - `[1]` boolean-value
/// - `[2]` real-value
/// - `[3]` enum-value (unsigned)
/// - `[4]` unsigned-value
/// - `[5]` signed-value
/// - `[6]` bitstring-value
/// - `[7]` null-value
/// - `[8]` failure (BACnetError)
/// - `[9]` time-change (REAL, clock-adjustment seconds)
/// - `[10]` any-value (raw application-tagged bytes)
#[derive(Debug, Clone, PartialEq)]
pub enum LogDatum {
    /// Log-status flags (context tag 0).  Bit 0=log-disabled, bit 1=buffer-purged,
    /// bit 2=log-interrupted.
    LogStatus(u8),
    /// Boolean value (context tag 1).
    BooleanValue(bool),
    /// Real (f32) value (context tag 2).
    RealValue(f32),
    /// Enumerated value (context tag 3).
    EnumValue(u32),
    /// Unsigned integer value (context tag 4).
    UnsignedValue(u64),
    /// Signed integer value (context tag 5).
    SignedValue(i64),
    /// Bit-string value (context tag 6).
    BitstringValue {
        /// Padding bits at the end of the final octet.
        unused_bits: u8,
        /// The bit data.
        data: Vec<u8>,
    },
    /// Null value (context tag 7).
    NullValue,
    /// Error (context tag 8): error class + error code.
    Failure {
        /// Raw BACnet error class value.
        error_class: u32,
        /// Raw BACnet error code value.
        error_code: u32,
    },
    /// Time-change: clock-adjustment amount in seconds (context tag 9).
    TimeChange(f32),
    /// Any-value: raw application-tagged bytes for types not enumerated above
    /// (context tag 10).
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
            LogValue::SignedValue(value) => Self::SignedValue(i64::from(value)),
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
// BACnetLogRecord (Clause 12.25 -- TrendLog Log_Buffer; Clause 21.6)
// ---------------------------------------------------------------------------

/// A single record stored in a TrendLog object's log buffer.
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
    /// Optional status flags at time of logging (4-bit BACnet StatusFlags).
    pub status_flags: Option<u8>,
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
    /// A value of another datatype, as its application-tagged encoding.
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
