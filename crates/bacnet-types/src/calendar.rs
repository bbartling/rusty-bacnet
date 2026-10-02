//! Calendar arithmetic and calendar-entry matching.
//!
//! One implementation of the date rules the Calendar object (Clause 12.9) and
//! the Schedule object (Clauses 12.24.4, 12.24.6 and 12.24.8) evaluate against
//! the device's local date:
//!
//! - A Date used as a pattern (Clause 20.2.12) is checked octet by octet. An
//!   unspecified octet (`0xFF`) matches anything; month 13 and 14 mean odd and
//!   even months; day 32, 33 and 34 mean the last day, odd days and even days.
//!   Every specified octet must match.
//! - A `BACnetDateRange` (Clause 21) holds two dates, each either a specific
//!   date or wholly unspecified. The Clause 12 note on unspecified dates makes
//!   an unspecified start or end leave that side of the range open, so both
//!   unspecified covers every date.
//! - A `BACnetWeekNDay` (Clause 21) matches month, week-of-month and weekday
//!   independently, `0xFF` matching any. Weeks 1 to 5 are days 1-7, 8-14,
//!   15-21, 22-28 and 29-31; week 6 is the last seven days of the month, and 7,
//!   8 and 9 are the seven days before the last 7, 14 and 21.
//!
//! The day being matched is a [`SpecificDate`]: a real day whose weekday is
//! computed from year, month and day, so a weekday octet that disagrees with
//! the rest of a received date (a local matter under Clause 20.2.12) never
//! changes the answer.

use crate::constructed::{BACnetCalendarEntry, BACnetDateRange, BACnetWeekNDay};
use crate::primitives::{Date, Time};

const ANY: u8 = 0xFF;

/// Whether `year` is a Gregorian leap year.
pub fn is_leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// The number of days in `month` (1 to 12) of `year`, or 0 for any other month.
pub fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// One real day of the Gregorian calendar within the years a BACnet Date can
/// carry (1900 to 2154).
///
/// Ordering is chronological.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpecificDate {
    year: u16,
    month: u8,
    day: u8,
}

impl SpecificDate {
    /// The day `year`-`month`-`day`, or `None` when no such day exists or the
    /// year is outside 1900 to 2154.
    pub fn new(year: u16, month: u8, day: u8) -> Option<Self> {
        let in_range =
            (1900..=2154).contains(&year) && (1..=days_in_month(year, month)).contains(&day);
        in_range.then_some(Self { year, month, day })
    }

    /// The day a Date names, or `None` unless its year, month and day are all
    /// specified and name a real day (no special month or day values).
    ///
    /// The weekday octet is ignored; [`weekday`](Self::weekday) computes it.
    pub fn from_date(date: &Date) -> Option<Self> {
        if date.year == ANY {
            return None;
        }
        Self::new(1900 + u16::from(date.year), date.month, date.day)
    }

    /// The year, 1900 to 2154.
    pub fn year(self) -> u16 {
        self.year
    }

    /// The month, 1 (January) to 12.
    pub fn month(self) -> u8 {
        self.month
    }

    /// The day of the month, from 1.
    pub fn day(self) -> u8 {
        self.day
    }

    /// The number of days in this day's month.
    pub fn days_in_month(self) -> u8 {
        days_in_month(self.year, self.month)
    }

    /// The day of the week, 1 (Monday) to 7 (Sunday), as BACnet numbers it.
    pub fn weekday(self) -> u8 {
        // Days since 1970-01-01 (a Thursday) by the civil-from-days inverse.
        let year = i64::from(self.year) - i64::from(self.month <= 2);
        let era = year.div_euclid(400);
        let year_of_era = year - era * 400;
        let month = i64::from(self.month);
        let month_prime = month + if month > 2 { -3 } else { 9 };
        let day_of_year = (153 * month_prime + 2) / 5 + i64::from(self.day) - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        let days = era * 146_097 + day_of_era - 719_468;
        (days + 3).rem_euclid(7) as u8 + 1
    }

    /// This day as a fully specified BACnet Date, weekday included.
    pub fn to_date(self) -> Date {
        Date {
            year: (self.year - 1900) as u8,
            month: self.month,
            day: self.day,
            day_of_week: self.weekday(),
        }
    }
}

/// Whether a month octet (a month, 13 for odd, 14 for even, or `0xFF`) admits
/// `month`.
fn month_matches(octet: u8, month: u8) -> bool {
    match octet {
        ANY => true,
        13 => !month.is_multiple_of(2),
        14 => month.is_multiple_of(2),
        specific => specific == month,
    }
}

/// Whether a weekday octet (1 to 7, or `0xFF`) admits `day`'s weekday.
fn weekday_matches(octet: u8, day: SpecificDate) -> bool {
    octet == ANY || octet == day.weekday()
}

/// Whether `octet` is a weekday (1 to 7) or unspecified.
fn valid_weekday(octet: u8) -> bool {
    octet == ANY || (1..=7).contains(&octet)
}

/// Whether `octet` is a month (1 to 12), odd or even months, or unspecified.
fn valid_month(octet: u8) -> bool {
    octet == ANY || (1..=14).contains(&octet)
}

impl Date {
    /// Whether every octet is unspecified, the date that matches any date.
    pub fn is_unspecified(&self) -> bool {
        self.encode() == [ANY; 4]
    }

    /// Whether every octet holds a value Clause 20.2.12 defines for a date
    /// pattern: any year; month 1 to 14; day 1 to 34; weekday 1 to 7; each of
    /// them, or all, unspecified.
    pub fn is_valid_pattern(&self) -> bool {
        valid_month(self.month)
            && (self.day == ANY || (1..=34).contains(&self.day))
            && valid_weekday(self.day_of_week)
    }

    /// Whether this date, read as a pattern, matches `day`: each specified
    /// octet must agree, including the odd, even and last-day values.
    pub fn matches(&self, day: SpecificDate) -> bool {
        let year = self.year == ANY || 1900 + u16::from(self.year) == day.year();
        let day_of_month = match self.day {
            ANY => true,
            32 => day.day() == day.days_in_month(),
            33 => !day.day().is_multiple_of(2),
            34 => day.day().is_multiple_of(2),
            specific => specific == day.day(),
        };
        year && month_matches(self.month, day.month())
            && day_of_month
            && weekday_matches(self.day_of_week, day)
    }
}

/// One end of a date range: open, a day, or neither (not a valid endpoint).
enum Endpoint {
    Open,
    At(SpecificDate),
    Invalid,
}

impl Endpoint {
    fn of(date: &Date) -> Self {
        if date.is_unspecified() {
            return Self::Open;
        }
        match SpecificDate::from_date(date) {
            Some(day) if valid_weekday(date.day_of_week) => Self::At(day),
            _ => Self::Invalid,
        }
    }
}

impl BACnetDateRange {
    /// Whether both dates are allowed endpoints: wholly unspecified, or a
    /// specific date (year, month and day naming a real day, with no special
    /// values). The weekday octet may be unspecified or disagree with the
    /// date, since it never changes which day the endpoint names.
    pub fn is_valid(&self) -> bool {
        !matches!(Endpoint::of(&self.start_date), Endpoint::Invalid)
            && !matches!(Endpoint::of(&self.end_date), Endpoint::Invalid)
    }

    /// Whether `day` falls within the range, both ends included; an
    /// unspecified end is open. A range with an invalid endpoint (see
    /// [`is_valid`](Self::is_valid)) contains no day, and so does one whose
    /// start is after its end.
    pub fn contains(&self, day: SpecificDate) -> bool {
        let after_start = match Endpoint::of(&self.start_date) {
            Endpoint::Open => true,
            Endpoint::At(start) => start <= day,
            Endpoint::Invalid => return false,
        };
        let before_end = match Endpoint::of(&self.end_date) {
            Endpoint::Open => true,
            Endpoint::At(end) => day <= end,
            Endpoint::Invalid => return false,
        };
        after_start && before_end
    }
}

impl BACnetWeekNDay {
    /// Whether each octet is in its Clause 21 range: month 1 to 14,
    /// week-of-month 1 to 9, weekday 1 to 7, each or all unspecified.
    pub fn is_valid(&self) -> bool {
        valid_month(self.month)
            && (self.week_of_month == ANY || (1..=9).contains(&self.week_of_month))
            && valid_weekday(self.day_of_week)
    }

    /// Whether `day` matches month, week-of-month and weekday.
    pub fn matches(&self, day: SpecificDate) -> bool {
        let date = day.day();
        let last = day.days_in_month();
        let week = match self.week_of_month {
            ANY => true,
            week @ 1..=5 => (date - 1) / 7 + 1 == week,
            // Week 6 ends on the last day; 7, 8 and 9 end 7, 14 and 21 days
            // earlier. Each spans the seven days ending there.
            week @ 6..=9 => {
                let end = i16::from(last) - i16::from(week - 6) * 7;
                (end - 6..=end).contains(&i16::from(date))
            }
            _ => false,
        };
        month_matches(self.month, day.month()) && week && weekday_matches(self.day_of_week, day)
    }
}

impl BACnetCalendarEntry {
    /// Whether the entry's values are all in range for its choice: a date
    /// pattern ([`Date::is_valid_pattern`]), a date range
    /// ([`BACnetDateRange::is_valid`]) or a week-n-day
    /// ([`BACnetWeekNDay::is_valid`]).
    pub fn is_valid(&self) -> bool {
        match self {
            Self::Date(date) => date.is_valid_pattern(),
            Self::DateRange(range) => range.is_valid(),
            Self::WeekNDay(week_n_day) => week_n_day.is_valid(),
        }
    }

    /// Whether `day` matches the entry.
    pub fn matches(&self, day: SpecificDate) -> bool {
        match self {
            Self::Date(date) => date.matches(day),
            Self::DateRange(range) => range.contains(day),
            Self::WeekNDay(week_n_day) => week_n_day.matches(day),
        }
    }
}

impl Time {
    /// Whether every field is specified and in range: hour 0 to 23, minute
    /// and second 0 to 59, hundredths 0 to 99.
    pub fn is_specific(&self) -> bool {
        self.hour <= 23 && self.minute <= 59 && self.second <= 59 && self.hundredths <= 99
    }
}

#[cfg(test)]
mod tests;
