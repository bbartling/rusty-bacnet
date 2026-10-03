//! Object-owned trend polling schedule. The caller owns synchronization and timers.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use bacnet_encoding::primitives::encode_property_value;
use bacnet_types::constructed::{
    BACnetLogMultipleRecord, BACnetLogRecord, LogData, LogDatum, LogValue,
};
use bacnet_types::enums::{ErrorClass, ErrorCode, ObjectType, PropertyIdentifier as P};
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};
use bytes::BytesMut;
use tracing::warn;

use super::{LocalDevice, ObjectDatabase};
use crate::traits::BACnetObject;

/// Local maximum idle/configuration reconciliation delay and failure backoff.
/// This is a scheduling policy, not a BACnet timing guarantee.
const RECONCILE: Duration = Duration::from_millis(100);

#[derive(PartialEq)]
struct Configuration {
    interval: u32,
    logging_type: u32,
    /// Log_DeviceObjectProperty as read, compared whole for scheduling
    /// ownership.
    reference: PropertyValue,
    /// What each acquisition reads: the one reference of a Trend Log, or every
    /// element of a Trend Log Multiple in array order.
    members: Vec<Member>,
}

/// One monitored reference of a log.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Member {
    /// A Trend Log Multiple element naming object or device instance 4194303,
    /// which Clause 12.30.11 treats as empty.
    Unspecified,
    /// A property to read, at one element when `index` is present.
    Reference {
        target: ObjectIdentifier,
        property: P,
        index: Option<u32>,
        /// The reference's optional Device member.
        device: Option<ObjectIdentifier>,
    },
}

struct Schedule {
    configuration: Configuration,
    last_success: Option<Duration>,
    /// Latest failed attempt, independent of the last accepted sample.
    retry_completed: Option<Duration>,
}

impl Schedule {
    fn remaining(&self, now: Duration) -> Duration {
        let (completed, wait) = match (self.retry_completed, self.last_success) {
            (Some(failed), _) => (failed, RECONCILE),
            (None, Some(success)) => (
                success,
                Duration::from_millis(u64::from(self.configuration.interval) * 10),
            ),
            (None, None) => return Duration::ZERO,
        };
        wait.saturating_sub(now.saturating_sub(completed))
    }
}

#[derive(Default)]
pub(super) struct TrendPollSchedule(HashMap<ObjectIdentifier, Schedule>);

impl TrendPollSchedule {
    pub(super) fn retire(&mut self, oid: &ObjectIdentifier) {
        self.0.remove(oid);
    }

    pub(super) fn clear(&mut self) {
        self.0.clear();
    }
}

impl ObjectDatabase {
    /// Poll every due local Trend Log or Trend Log Multiple synchronously and
    /// return the next wait.
    ///
    /// Each acquisition reads every reference of the log: a Trend Log's one,
    /// or each Log_DeviceObjectProperty element of a Trend Log Multiple, whose
    /// record then carries one value per element in array order (#1203).
    /// Only this database is read. A reference whose Device member names
    /// another device (see [`ObjectDatabase::local_device`]) is never read
    /// here, even when a same-numbered local object exists: its value is a
    /// failure, PROPERTY / OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED. A Trend Log
    /// Multiple element naming instance 4194303 is empty and fails with
    /// PROPERTY / NO_PROPERTY_SPECIFIED. A reference with an array index reads
    /// that element (#1205). A local read that fails yields the error a
    /// ReadProperty of it would report: OBJECT / UNKNOWN_OBJECT for a missing
    /// object, PROPERTY / PROPERTY_IS_NOT_AN_ARRAY for an index on a property
    /// that isn't an array, or the read's own error, such as INVALID_ARRAY_INDEX
    /// for an index past the end (#1183).
    ///
    /// Only POLLED logs with a nonzero Log_Interval and at least one reference
    /// are polled. The caller must hold exclusive database access for this
    /// whole call. The bound monotonic clock drives scheduling; the shared
    /// Device clock provides each actual acquisition timestamp. Without either
    /// clock an attempt cannot succeed. A successful call to an object's
    /// insertion hook, including its accepted disabled/count-only outcomes,
    /// starts the configured interval.
    ///
    /// Log_Interval is in hundredths. Deadlines follow actual completion, without
    /// catch-up bursts. Invalid timestamps and insertion errors preserve the last
    /// success and retry after 100 ms. The returned wait is at most 100 ms so a
    /// timer-driven caller also reconciles configuration changes and idle logs.
    /// Slow synchronous work can make another object due; a minimum 1 ms yield
    /// avoids a zero-delay loop. These bounds are local policy, not real-time
    /// guarantees. Clock, object reads and insertion hooks must remain bounded.
    pub fn poll_trend_logs(&mut self) -> Duration {
        let Some(monotonic) = self.monotonic_clock.clone() else {
            return RECONCILE;
        };
        let mut eligible = HashSet::new();
        let local = self.local_device();
        let mut logs = self.find_by_type(ObjectType::TREND_LOG);
        logs.extend(self.find_by_type(ObjectType::TREND_LOG_MULTIPLE));
        for oid in logs {
            let Some(configuration) = self.get(&oid).and_then(configuration) else {
                continue;
            };
            eligible.insert(oid);
            if self
                .trend_poll
                .0
                .get(&oid)
                .is_none_or(|entry| entry.configuration != configuration)
            {
                self.trend_poll.0.insert(
                    oid,
                    Schedule {
                        configuration,
                        last_success: None,
                        retry_completed: None,
                    },
                );
            }
            if !self.trend_poll.0[&oid].remaining(monotonic()).is_zero() {
                continue;
            }
            let accepted = self
                .clock_frame()
                .filter(|frame| frame.is_valid_actual_datetime())
                .map(|frame| {
                    let values: Vec<LogValue> = self.trend_poll.0[&oid]
                        .configuration
                        .members
                        .iter()
                        .map(|member| self.acquire(local, member))
                        .collect();
                    // Exclusive access prevents structural change after selection.
                    let object = self.get_mut(&oid).unwrap();
                    let inserted = if oid.object_type() == ObjectType::TREND_LOG_MULTIPLE {
                        object.add_trend_multiple_record(BACnetLogMultipleRecord {
                            date: frame.local_date,
                            time: frame.local_time,
                            log_data: LogData::Values(values),
                        })
                    } else {
                        object.add_trend_record(BACnetLogRecord {
                            date: frame.local_date,
                            time: frame.local_time,
                            // A Trend Log has exactly one reference.
                            log_datum: values
                                .into_iter()
                                .next()
                                .map_or(LogDatum::NullValue, LogDatum::from),
                            status_flags: None,
                        })
                    };
                    match inserted {
                        Ok(()) => true,
                        Err(error) => {
                            warn!(object = %oid, %error, "trend-log record insertion failed");
                            false
                        }
                    }
                })
                .unwrap_or(false);
            let completed = monotonic();
            let entry = self.trend_poll.0.get_mut(&oid).unwrap();
            if accepted {
                entry.last_success = Some(completed);
                entry.retry_completed = None;
            } else {
                entry.retry_completed = Some(completed);
            }
        }
        self.trend_poll.0.retain(|oid, _| eligible.contains(oid));
        let now = monotonic();
        let remaining = self
            .trend_poll
            .0
            .values()
            .map(|entry| entry.remaining(now))
            .min()
            .unwrap_or(RECONCILE)
            .min(RECONCILE);
        if remaining.is_zero() {
            Duration::from_millis(1)
        } else {
            remaining
        }
    }

    /// One reference's value, or the failure that stopped its read
    /// (Clause 12.25 Log_Buffer; Clause 12.30.19 for each member).
    fn acquire(&self, local: LocalDevice, member: &Member) -> LogValue {
        let Member::Reference {
            target,
            property,
            index,
            device,
        } = *member
        else {
            return failure(ErrorClass::PROPERTY, ErrorCode::NO_PROPERTY_SPECIFIED);
        };
        if !local.is_local(device) {
            // Reading another device's property is not supported here.
            return failure(
                ErrorClass::PROPERTY,
                ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED,
            );
        }
        let Some(target) = self.get(&target) else {
            return failure(ErrorClass::OBJECT, ErrorCode::UNKNOWN_OBJECT);
        };
        // ReadProperty's gate, which the Averaging sampler shares: only an
        // array has elements, whatever an object's read arm does with the
        // index.
        if index.is_some() && !target.is_array_property(property) {
            return failure(ErrorClass::PROPERTY, ErrorCode::PROPERTY_IS_NOT_AN_ARRAY);
        }
        match target.read_property(property, index) {
            Ok(value) => property_value_to_log_value(&value),
            Err(Error::Protocol { class, code } | Error::Structured { class, code, .. }) => {
                LogValue::Failure {
                    error_class: class,
                    error_code: code,
                }
            }
            // An error with no BACnet class and code reports as ReadProperty
            // would answer it.
            Err(_) => failure(ErrorClass::SERVICES, ErrorCode::OTHER),
        }
    }
}

fn failure(class: ErrorClass, code: ErrorCode) -> LogValue {
    LogValue::Failure {
        error_class: u32::from(class.to_raw()),
        error_code: u32::from(code.to_raw()),
    }
}

fn configuration(object: &dyn BACnetObject) -> Option<Configuration> {
    let PropertyValue::Unsigned(raw) = object.read_property(P::LOG_INTERVAL, None).ok()? else {
        return None;
    };
    let interval = u32::try_from(raw).ok().filter(|value| *value > 0)?;
    let logging_type = match object.read_property(P::LOGGING_TYPE, None) {
        Ok(PropertyValue::Enumerated(value)) => value,
        _ => 0,
    };
    if matches!(logging_type, 1 | 2) {
        return None;
    }
    let reference = object
        .read_property(P::LOG_DEVICE_OBJECT_PROPERTY, None)
        .ok()?;
    let members = if object.object_identifier().object_type() == ObjectType::TREND_LOG_MULTIPLE {
        let PropertyValue::List(elements) = &reference else {
            return None;
        };
        elements
            .iter()
            .map(|element| member(element, true))
            .collect::<Option<Vec<_>>>()?
    } else {
        vec![member(&reference, false)?]
    };
    if members.is_empty() {
        return None;
    }
    Some(Configuration {
        interval,
        logging_type,
        reference,
        members,
    })
}

/// One reference as a read projects it: object, property, then optional
/// array index and Device, each Null when absent. Anything else leaves the
/// log unpolled: a malformed index or Device can't be honoured, nor a Device
/// told local or remote. `wildcard_is_empty` applies the Trend Log Multiple
/// rule for instance 4194303.
fn member(value: &PropertyValue, wildcard_is_empty: bool) -> Option<Member> {
    let PropertyValue::List(items) = value else {
        return None;
    };
    let [PropertyValue::ObjectIdentifier(target), PropertyValue::Unsigned(property), rest @ ..] =
        items.as_slice()
    else {
        return None;
    };
    let index = match rest.first() {
        None | Some(PropertyValue::Null) => None,
        Some(PropertyValue::Unsigned(index)) => Some(u32::try_from(*index).ok()?),
        Some(_) => return None,
    };
    let device = match rest.get(1) {
        None | Some(PropertyValue::Null) => None,
        Some(PropertyValue::ObjectIdentifier(device)) => Some(*device),
        Some(_) => return None,
    };
    let property = P::from_raw(u32::try_from(*property).ok()?);
    let empty =
        |oid: &ObjectIdentifier| oid.instance_number() == ObjectIdentifier::WILDCARD_INSTANCE;
    if wildcard_is_empty && (empty(target) || device.as_ref().is_some_and(empty)) {
        return Some(Member::Unspecified);
    }
    Some(Member::Reference {
        target: *target,
        property,
        index,
        device,
    })
}

/// A read value as the log stores it: one of the datatypes both record kinds
/// name, or else the any-value alternative holding the value's own encoding,
/// the bytes a ReadProperty of it would carry (Clauses 12.25.14 and
/// 12.30.19).
fn property_value_to_log_value(value: &PropertyValue) -> LogValue {
    match value {
        PropertyValue::Real(v) => LogValue::RealValue(*v),
        PropertyValue::Unsigned(v) => LogValue::UnsignedValue(*v),
        PropertyValue::Signed(v) => LogValue::SignedValue(*v),
        PropertyValue::Boolean(v) => LogValue::BooleanValue(*v),
        PropertyValue::Enumerated(v) => LogValue::EnumValue(*v),
        PropertyValue::BitString { unused_bits, data } => LogValue::BitstringValue {
            unused_bits: *unused_bits,
            data: data.clone(),
        },
        PropertyValue::Null => LogValue::NullValue,
        other => {
            let mut encoded = BytesMut::new();
            match encode_property_value(&mut encoded, other) {
                Ok(()) => LogValue::AnyValue(encoded.to_vec()),
                // A value the read could not have carried either.
                Err(_) => failure(ErrorClass::SERVICES, ErrorCode::OTHER),
            }
        }
    }
}

#[cfg(test)]
mod tests;
