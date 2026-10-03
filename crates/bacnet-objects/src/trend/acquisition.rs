//! How a Trend Log Multiple acquires its records (Clauses 12.30.12 to
//! 12.30.16): Logging_Type, Log_Interval, Align_Intervals, Interval_Offset
//! and Trigger. The database's trend poller reads these rows to schedule
//! acquisitions; the object owns their values and write rules.

use bacnet_types::enums::{ErrorClass, ErrorCode, LoggingType, PropertyIdentifier as P};
use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;

use crate::common;

/// The Log_Interval a Trend Log Multiple takes, in hundredths of a second (one
/// minute), when POLLED is chosen while its Log_Interval is zero. Clause
/// 12.30.12 leaves the default to the device.
pub const DEFAULT_LOG_INTERVAL: u32 = 6_000;

/// A Trend Log Multiple's acquisition settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Acquisition {
    logging_type: LoggingType,
    /// Hundredths of a second; zero while TRIGGERED.
    log_interval: u32,
    align_intervals: bool,
    interval_offset: u32,
    trigger: bool,
}

impl Default for Acquisition {
    /// POLLED with no interval, so nothing is acquired until one is set.
    fn default() -> Self {
        Self {
            logging_type: LoggingType::POLLED,
            log_interval: 0,
            align_intervals: false,
            interval_offset: 0,
            trigger: false,
        }
    }
}

impl Acquisition {
    pub(super) fn logging_type(&self) -> LoggingType {
        self.logging_type
    }

    /// Serve one of the five rows; `None` for any other property.
    pub(super) fn read(&self, property: P) -> Option<PropertyValue> {
        Some(match property {
            P::LOGGING_TYPE => PropertyValue::Enumerated(self.logging_type.to_raw()),
            P::LOG_INTERVAL => PropertyValue::Unsigned(self.log_interval.into()),
            P::ALIGN_INTERVALS => PropertyValue::Boolean(self.align_intervals),
            P::INTERVAL_OFFSET => PropertyValue::Unsigned(self.interval_offset.into()),
            P::TRIGGER => PropertyValue::Boolean(self.trigger),
            _ => return None,
        })
    }

    /// A write of one of the five rows, a client's or a local process's;
    /// `None` for any other property, and for Log_Interval while TRIGGERED,
    /// when it is read-only (Table 12-35 footnote 2) and the caller refuses
    /// it as it refuses any read-only row.
    pub(super) fn write(
        &mut self,
        property: P,
        value: &PropertyValue,
    ) -> Option<Result<(), Error>> {
        Some(match (property, value) {
            (P::LOGGING_TYPE, PropertyValue::Enumerated(raw)) => {
                self.set_logging_type(LoggingType::from_raw(*raw))
            }
            (P::LOG_INTERVAL, _) if self.logging_type == LoggingType::TRIGGERED => return None,
            (P::LOG_INTERVAL | P::INTERVAL_OFFSET, PropertyValue::Unsigned(raw)) => {
                common::u64_to_u32(*raw).map(|hundredths| {
                    if property == P::LOG_INTERVAL {
                        self.log_interval = hundredths;
                    } else {
                        self.interval_offset = hundredths;
                    }
                })
            }
            (P::ALIGN_INTERVALS, PropertyValue::Boolean(align)) => {
                self.align_intervals = *align;
                Ok(())
            }
            (P::TRIGGER, PropertyValue::Boolean(trigger)) => self.write_trigger(*trigger),
            (
                P::LOGGING_TYPE
                | P::LOG_INTERVAL
                | P::INTERVAL_OFFSET
                | P::ALIGN_INTERVALS
                | P::TRIGGER,
                _,
            ) => Err(common::invalid_data_type_error()),
            _ => return None,
        })
    }

    /// Choose POLLED or TRIGGERED acquisition (Clause 12.30.12). COV, which
    /// a Trend Log Multiple doesn't do, and any other value are PROPERTY /
    /// VALUE_OUT_OF_RANGE and change nothing. POLLED with a zero Log_Interval
    /// sets [`DEFAULT_LOG_INTERVAL`]; TRIGGERED sets Log_Interval to zero.
    /// Leaving TRIGGERED drops a Trigger not yet acted on.
    pub(super) fn set_logging_type(&mut self, logging_type: LoggingType) -> Result<(), Error> {
        match logging_type {
            LoggingType::POLLED => {
                if self.log_interval == 0 {
                    self.log_interval = DEFAULT_LOG_INTERVAL;
                }
                self.trigger = false;
            }
            LoggingType::TRIGGERED => self.log_interval = 0,
            _ => return Err(common::value_out_of_range_error()),
        }
        self.logging_type = logging_type;
        Ok(())
    }

    /// Set Log_Interval as local configuration, held to the network rule:
    /// while TRIGGERED it is read-only, PROPERTY / WRITE_ACCESS_DENIED.
    pub(super) fn set_log_interval(&mut self, hundredths: u32) -> Result<(), Error> {
        if self.logging_type == LoggingType::TRIGGERED {
            return Err(common::write_access_denied_error());
        }
        self.log_interval = hundredths;
        Ok(())
    }

    pub(super) fn set_align_intervals(&mut self, align: bool) {
        self.align_intervals = align;
    }

    pub(super) fn set_interval_offset(&mut self, hundredths: u32) {
        self.interval_offset = hundredths;
    }

    /// Trigger is set TRUE to ask for one acquisition, which the poller
    /// makes and then clears it (Clause 12.30.16). Only a TRIGGERED log takes
    /// it: TRUE on any other is PROPERTY /
    /// NOT_CONFIGURED_FOR_TRIGGERED_LOGGING. FALSE is accepted and changes
    /// nothing, so an acquisition already asked for still happens.
    fn write_trigger(&mut self, trigger: bool) -> Result<(), Error> {
        if !trigger {
            return Ok(());
        }
        if self.logging_type != LoggingType::TRIGGERED {
            return Err(common::protocol_error(
                ErrorClass::PROPERTY,
                ErrorCode::NOT_CONFIGURED_FOR_TRIGGERED_LOGGING,
            ));
        }
        self.trigger = true;
        Ok(())
    }

    /// Set Trigger TRUE as a local process would.
    pub(super) fn trigger(&mut self) -> Result<(), Error> {
        self.write_trigger(true)
    }

    /// A record was acquired: a pending Trigger has been served.
    pub(super) fn acquired(&mut self) {
        self.trigger = false;
    }
}
