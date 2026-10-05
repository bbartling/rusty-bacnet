//! The one year convention for a Date crossing into or out of Python (#1501).
//!
//! Python reads and writes a Date as `(year, month, day, day_of_week)` with
//! the full year, 1900..=2154, and 255 for an unspecified year, the same 255
//! every other unspecified date or time field holds. No full year is 255, so
//! the two never meet. A `PropertyValue` date, a `BACnetTimeStamp`, the typed
//! constructed forms (schedules, calendars, date ranges), the audit log's
//! records and the time synchronization requests all go through here.

use super::*;

/// The year an unspecified year reads and writes as.
pub(crate) const UNSPECIFIED_YEAR: u16 = 255;

/// The full year of `date`, or [`UNSPECIFIED_YEAR`].
pub(crate) fn full_year(date: &primitives::Date) -> u16 {
    date.actual_year().unwrap_or(UNSPECIFIED_YEAR)
}

/// The year octet for `year`, a full year or [`UNSPECIFIED_YEAR`]; any other
/// year raises ValueError naming `name`.
pub(crate) fn year_octet(year: u16, name: &str) -> PyResult<u8> {
    match year {
        UNSPECIFIED_YEAR => Ok(primitives::Date::UNSPECIFIED),
        1900..=2154 => Ok(u8::try_from(year - 1900).expect("1900..=2154 is 0..=254 past 1900")),
        _ => Err(PyValueError::new_err(format!(
            "{name} must be 1900..=2154 or 255 (unspecified), got {year}"
        ))),
    }
}

/// `date` as Python reads it: `(year, month, day, day_of_week)`.
pub(crate) fn date_value(date: &primitives::Date) -> (u16, u8, u8, u8) {
    (full_year(date), date.month, date.day, date.day_of_week)
}

/// The Date Python's `(year, month, day, day_of_week)` names. Only the year
/// is checked: the other fields are octets, taken as given.
pub(crate) fn date_from_value(
    (year, month, day, day_of_week): (u16, u8, u8, u8),
) -> PyResult<primitives::Date> {
    Ok(primitives::Date {
        year: year_octet(year, "year")?,
        month,
        day,
        day_of_week,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_year_octet_has_one_python_year_and_back() {
        for octet in 0..=u8::MAX {
            let date = primitives::Date {
                year: octet,
                month: 1,
                day: 2,
                day_of_week: 3,
            };
            let (year, ..) = date_value(&date);
            let expected = if octet == primitives::Date::UNSPECIFIED {
                UNSPECIFIED_YEAR
            } else {
                1900 + u16::from(octet)
            };
            assert_eq!(year, expected);
            assert_eq!(date_from_value(date_value(&date)).unwrap(), date);
        }
    }

    #[test]
    fn a_year_neither_full_nor_unspecified_is_refused() {
        for year in [0, 126, 254, 256, 1899, 2155, u16::MAX] {
            assert!(year_octet(year, "year").is_err(), "{year}");
        }
    }
}
