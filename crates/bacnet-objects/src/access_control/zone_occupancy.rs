//! Occupancy counting on an Access Zone (Clauses 12.32.6 and 12.32.11 to
//! 12.32.15, #1284).
//!
//! The zone always supports counting, so it serves Occupancy_Count,
//! Occupancy_Count_Enable and Adjust_Value (footnote 4 of Table 12-37 ties
//! the three to that support) and both occupancy limits. Occupancy_State is
//! worked out on each read from what the zone serves:
//!
//! - DISABLED while Occupancy_Count_Enable is FALSE;
//! - otherwise BELOW_LOWER_LIMIT, AT_LOWER_LIMIT, AT_UPPER_LIMIT or
//!   ABOVE_UPPER_LIMIT as the served count compares with a limit, a limit of
//!   zero being no limit at all;
//! - NORMAL when no limit applies.
//!
//! A limit pair is set as one call, so the rule that a nonzero upper limit
//! sits above the lower one is checked on the pair; both limits and the
//! enable are read-only over the network, since Table 12-37 marks them O.
//!
//! While counting is off the count is zero (12.32.11): turning it off zeroes
//! the count served, the count set aside for an out-of-service period and
//! Adjust_Value, and while it stays off the application's counts are
//! dropped and a simulated count other than zero is VALUE_OUT_OF_RANGE.
//! Turning counting back on starts again from zero, the choice 12.32.12
//! leaves to the implementation.
//!
//! Adjust_Value is the zone's one writable counting row (footnote 5). With
//! counting on, a written value is kept and moves the count: a nonzero value
//! is added, the sum stopping at zero, and zero clears the count. While
//! Out_Of_Service is TRUE the value is kept but the count stays as the client
//! simulates it (12.32.10). With counting off, any write leaves Adjust_Value
//! at zero.

use bacnet_types::enums::AccessZoneOccupancyState;
use bacnet_types::error::Error;

use crate::common;

/// The counting configuration of an Access Zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Occupancy {
    /// Occupancy_Count_Enable.
    pub(super) enabled: bool,
    /// Adjust_Value: the last value written while counting was on.
    pub(super) adjust_value: i32,
    /// Occupancy_Lower_Limit; zero is no lower limit.
    pub(super) lower_limit: u64,
    /// Occupancy_Upper_Limit; zero is no upper limit.
    pub(super) upper_limit: u64,
}

impl Occupancy {
    /// Counting on, nothing adjusted yet and no limits.
    pub(super) const NEW: Self = Self {
        enabled: true,
        adjust_value: 0,
        lower_limit: 0,
        upper_limit: 0,
    };

    /// Occupancy_State for a zone serving `count`.
    pub(super) fn state(&self, count: u64) -> AccessZoneOccupancyState {
        let lower = self.lower_limit;
        let upper = self.upper_limit;
        if !self.enabled {
            AccessZoneOccupancyState::DISABLED
        } else if lower != 0 && count < lower {
            AccessZoneOccupancyState::BELOW_LOWER_LIMIT
        } else if lower != 0 && count == lower {
            AccessZoneOccupancyState::AT_LOWER_LIMIT
        } else if upper != 0 && count > upper {
            AccessZoneOccupancyState::ABOVE_UPPER_LIMIT
        } else if upper != 0 && count == upper {
            AccessZoneOccupancyState::AT_UPPER_LIMIT
        } else {
            AccessZoneOccupancyState::NORMAL
        }
    }

    /// Replace both limits, or VALUE_OUT_OF_RANGE, changing neither, for a
    /// nonzero upper limit at or below the lower one (12.32.14).
    pub(super) fn set_limits(&mut self, lower: u64, upper: u64) -> Result<(), Error> {
        if upper != 0 && upper <= lower {
            return Err(common::value_out_of_range_error());
        }
        self.lower_limit = lower;
        self.upper_limit = upper;
        Ok(())
    }
}

/// `count` moved by a written Adjust_Value: a nonzero value added, stopping
/// at zero and at the top of the Unsigned range, and zero clearing it.
pub(super) fn adjusted(count: u64, adjust: i32) -> u64 {
    match adjust {
        0 => 0,
        up if up > 0 => count.saturating_add(up.unsigned_abs().into()),
        down => count.saturating_sub(down.unsigned_abs().into()),
    }
}
