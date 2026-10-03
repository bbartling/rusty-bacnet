//! Object-owned trend polling schedule. The caller owns synchronization and timers.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use bacnet_types::constructed::{BACnetLogRecord, LogDatum};
use bacnet_types::enums::{ErrorClass, ErrorCode, ObjectType, PropertyIdentifier as P};
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};
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
    reference: PropertyValue,
    target: ObjectIdentifier,
    property: P,
    /// The reference's optional Device member.
    device: Option<ObjectIdentifier>,
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
    /// Poll due local TrendLog references synchronously and return the next wait.
    ///
    /// Only this database is read. A reference whose Device member names
    /// another device (see [`ObjectDatabase::local_device`]) is never read
    /// here, even when a same-numbered local object exists: each due poll
    /// logs a failure record for it instead, PROPERTY /
    /// OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED. A local read that fails logs a
    /// failure record with the error a ReadProperty of it would report:
    /// OBJECT / UNKNOWN_OBJECT for a missing object, or the read's own error
    /// (#1183).
    ///
    /// The caller must hold exclusive database access for this whole call. The
    /// bound monotonic clock drives scheduling; the shared Device clock provides
    /// each actual acquisition timestamp. Without either clock an attempt cannot
    /// succeed. A successful call to an object's insertion hook, including its
    /// accepted disabled/count-only outcomes, starts the configured interval.
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
        for oid in self.find_by_type(ObjectType::TREND_LOG) {
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
            let entry = self.trend_poll.0.get(&oid).unwrap();
            if !entry.remaining(monotonic()).is_zero() {
                continue;
            }
            let target = entry.configuration.target;
            let property = entry.configuration.property;
            let device = entry.configuration.device;
            let accepted = self
                .clock_frame()
                .filter(|frame| frame.is_valid_actual_datetime())
                .map(|frame| {
                    let datum = self.acquire(local, device, target, property);
                    let record = BACnetLogRecord {
                        date: frame.local_date,
                        time: frame.local_time,
                        log_datum: datum,
                        status_flags: None,
                    };
                    // Exclusive access prevents structural change after selection.
                    match self.get_mut(&oid).unwrap().add_trend_record(record) {
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

    /// One acquisition: the datum read from `target`'s `property`, or the
    /// failure that stopped the read (Clause 12.25, Log_Buffer).
    fn acquire(
        &self,
        local: LocalDevice,
        device: Option<ObjectIdentifier>,
        target: ObjectIdentifier,
        property: P,
    ) -> LogDatum {
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
        match target.read_property(property, None) {
            Ok(value) => property_value_to_log_datum(&value),
            Err(Error::Protocol { class, code } | Error::Structured { class, code, .. }) => {
                LogDatum::Failure {
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

fn failure(class: ErrorClass, code: ErrorCode) -> LogDatum {
    LogDatum::Failure {
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
    let PropertyValue::List(items) = &reference else {
        return None;
    };
    let [PropertyValue::ObjectIdentifier(target), PropertyValue::Unsigned(property), rest @ ..] =
        items.as_slice()
    else {
        return None;
    };
    // A Device member that isn't an identifier can't be told local or remote.
    let device = match rest.get(1) {
        None | Some(PropertyValue::Null) => None,
        Some(PropertyValue::ObjectIdentifier(device)) => Some(*device),
        Some(_) => return None,
    };
    // Retain the existing unindexed read behavior. The full reference is
    // compared for scheduling ownership, without adding indexed support.
    Some(Configuration {
        interval,
        logging_type,
        target: *target,
        property: P::from_raw(*property as u32),
        device,
        reference,
    })
}

fn property_value_to_log_datum(value: &PropertyValue) -> LogDatum {
    match value {
        PropertyValue::Real(v) => LogDatum::RealValue(*v),
        PropertyValue::Unsigned(v) => LogDatum::UnsignedValue(*v),
        PropertyValue::Signed(v) => LogDatum::SignedValue(i64::from(*v)),
        PropertyValue::Boolean(v) => LogDatum::BooleanValue(*v),
        PropertyValue::Enumerated(v) => LogDatum::EnumValue(*v),
        _ => LogDatum::NullValue,
    }
}

#[cfg(test)]
mod tests;
