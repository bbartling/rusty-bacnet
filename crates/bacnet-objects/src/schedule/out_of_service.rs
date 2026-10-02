//! Present_Value while Out_Of_Service is TRUE (Clauses 12.24.4 and 12.24.14,
//! #1055).
//!
//! Out of service, the calculation stops driving Present_Value: a tick leaves
//! it alone, whatever the schedules say, and a client may write it instead.
//! In service a write is WRITE_ACCESS_DENIED. A written value must be of a
//! primitive datatype, NULL included, the check the time-values and
//! Schedule_Default get (INVALID_DATA_TYPE otherwise).
//!
//! The standard has the rest of the object react to such a write as it would
//! to a calculated change, so the written value goes on to
//! List_Of_Object_Property_References at Priority_For_Writing, a NULL
//! relinquishing. The object keeps the value owed and the server collects it
//! through `take_owed_schedule_writes` in the pass that also carries the
//! calculated writes: at once after the write commits, or at the next tick
//! for a write made on the object directly. A change of the references or
//! the priority while out of service owes the current value the same way
//! (`targets.rs`). Local choices:
//!
//! - Every accepted write is owed, even of the value already held, so the
//!   targets end up holding what Present_Value reads.
//! - Several writes before the pass collects them owe only the last value.
//! - The owed value goes out whether or not today falls in Effective_Period,
//!   and whatever Out_Of_Service is by the time it is collected: a
//!   WritePropertyMultiple that writes Present_Value and then returns the
//!   object to service still delivers it, ahead of the calculated value.
//!
//! When Out_Of_Service returns to FALSE the calculation owns Present_Value
//! again, and the bundled server runs it at once, as after any committed
//! write to a Schedule.
//!
//! Present_Value is not among the properties Reliability's consistency check
//! covers (Clause 12.24.13), so a written value of another datatype raises no
//! fault, even when a target refuses it; a target refusing one of the
//! schedule's own datatype counts as a calculated refusal would
//! (`reliability.rs`). A Reliability the client simulates meanwhile is left
//! as it is. A written value reaches the targets whatever Reliability holds,
//! as calculated values do.

use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;

use super::ScheduleObject;
use crate::common;

impl ScheduleObject {
    /// WriteProperty of Present_Value: only while Out_Of_Service is TRUE.
    pub(super) fn write_present_value(
        &mut self,
        array_index: Option<u32>,
        value: PropertyValue,
    ) -> Result<(), Error> {
        if !self.out_of_service {
            return Err(common::write_access_denied_error());
        }
        if array_index.is_some() {
            return Err(common::property_is_not_an_array_error());
        }
        if !value.is_primitive() {
            return Err(common::invalid_data_type_error());
        }
        self.present_value = value.clone();
        self.simulated_write = Some(value);
        Ok(())
    }
}
