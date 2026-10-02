//! The Schedule's own Reliability evaluation (#1056).
//!
//! Clause 12.24.13 ties Reliability to the schedule's configuration being
//! consistent. The half this object can check on its own is the contents:
//! leaving NULLs aside, every value in Weekly_Schedule, Exception_Schedule
//! and Schedule_Default must be of a single datatype. When they are not,
//! Reliability is CONFIGURATION_ERROR, and Status_Flags reports FAULT through
//! the usual Reliability mapping.
//!
//! The other half, whether every referenced property accepts that datatype,
//! needs the target objects, which only the database holds; it is not
//! evaluated here.
//!
//! A misconfigured schedule keeps evaluating and writing its references.
//! Clause 12.24.4 makes those writes unconditional, Reliability only reports
//! the inconsistency, and a target that cannot take a value refuses that one
//! write without stopping the others. The multi-state objects treat their
//! CONFIGURATION_ERROR the same way.
//!
//! The evaluation owns only the fault it raised. A Reliability applied through
//! `set_reliability_internal` stays until that caller changes it, and while
//! Out_Of_Service is TRUE the client's simulated value is left alone; the
//! return to service restores the saved value and evaluates again.

use bacnet_types::enums::Reliability;
use bacnet_types::primitives::PropertyValue;

use super::ScheduleObject;
use crate::traits::ReliabilityEvaluation;

impl ScheduleObject {
    /// Whether the non-NULL values of Weekly_Schedule, Exception_Schedule and
    /// Schedule_Default are all of one datatype. With no such values at all
    /// there is nothing to disagree.
    pub(super) fn values_share_one_datatype(&self) -> bool {
        let weekly = self.weekly_schedule.iter().flatten();
        let exceptions = self
            .exception_schedule
            .iter()
            .flat_map(|event| &event.list_of_time_values);
        let mut datatypes = weekly
            .chain(exceptions)
            .map(|time_value| &time_value.value)
            .chain(std::iter::once(&self.schedule_default))
            .filter(|value| **value != PropertyValue::Null)
            .map(std::mem::discriminant);
        match datatypes.next() {
            Some(first) => datatypes.all(|datatype| datatype == first),
            None => true,
        }
    }

    /// Re-run the consistency check after the contents changed or the object
    /// returned to service.
    ///
    /// Raises CONFIGURATION_ERROR over NO_FAULT_DETECTED, and clears it only
    /// if this evaluation raised it. Does nothing while Out_Of_Service is
    /// TRUE.
    pub(super) fn recompute_reliability(&mut self) -> ReliabilityEvaluation {
        if self.out_of_service {
            return ReliabilityEvaluation::Unchanged;
        }
        let misconfigured = !self.values_share_one_datatype();
        let new_reliability = if self.owns_configuration_error {
            if misconfigured {
                Reliability::CONFIGURATION_ERROR
            } else {
                Reliability::NO_FAULT_DETECTED
            }
        } else if misconfigured && self.reliability == Reliability::NO_FAULT_DETECTED {
            Reliability::CONFIGURATION_ERROR
        } else {
            return ReliabilityEvaluation::Unchanged;
        };
        self.owns_configuration_error = misconfigured;
        if new_reliability == self.reliability {
            return ReliabilityEvaluation::Unchanged;
        }
        let old_reliability = std::mem::replace(&mut self.reliability, new_reliability);
        ReliabilityEvaluation::Changed {
            old_reliability,
            new_reliability,
        }
    }
}
