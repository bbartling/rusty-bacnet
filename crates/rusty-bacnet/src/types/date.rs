//! The one year convention for a Date crossing into or out of Python (#1501).
//!
//! Python reads and writes a Date as `(year, month, day, day_of_week)` with
//! the full year, 1900..=2154, and 255 for an unspecified year, the same 255
//! every other unspecified date or time field holds (`rusty_bacnet.UNSPECIFIED`).
//! No full year is 255, so the two never meet. A `PropertyValue` date, a
//! `BACnetTimeStamp`, the typed constructed forms (schedules, calendars, date
//! ranges), the audit log's records and the time synchronization requests
//! all go through here.

use bacnet_types::calendar::SpecificDate;

use super::*;

/// What any unspecified date or time field reads and writes as in Python,
/// exported as `rusty_bacnet.UNSPECIFIED`.
pub(crate) const UNSPECIFIED: u8 = 255;

/// The year an unspecified year reads and writes as.
pub(crate) const UNSPECIFIED_YEAR: u16 = UNSPECIFIED as u16;

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

/// The date and time a TimeSynchronization or UTCTimeSynchronization request
/// carries, which set a clock and so must be specific (Clauses 16.7, 16.8,
/// 20.2.12): a real day in 1900..=2154 with no field unspecified or a
/// pattern value, its `day_of_week` the day's own weekday (1 = Monday), and
/// every time field in range. Anything else raises ValueError, before a
/// request is built.
pub(crate) fn specific_date_time(
    date: (u16, u8, u8, u8),
    (hour, minute, second, hundredths): (u8, u8, u8, u8),
) -> PyResult<(primitives::Date, primitives::Time)> {
    let parsed = date_from_value(date)?;
    let day = SpecificDate::from_date(&parsed).ok_or_else(|| {
        PyValueError::new_err(format!(
            "date must be a real day in 1900..=2154 with no field unspecified (255) \
             or a pattern value, got {date:?}"
        ))
    })?;
    if parsed.day_of_week != day.weekday() {
        return Err(PyValueError::new_err(format!(
            "day_of_week must be {} (1 = Monday) for {}-{:02}-{:02}, got {}",
            day.weekday(),
            day.year(),
            day.month(),
            day.day(),
            parsed.day_of_week
        )));
    }
    let time = primitives::Time {
        hour,
        minute,
        second,
        hundredths,
    };
    if !time.is_specific() {
        return Err(PyValueError::new_err(format!(
            "time must be specific: hour 0..=23, minute and second 0..=59, \
             hundredths 0..=99, got {:?}",
            (hour, minute, second, hundredths)
        )));
    }
    Ok((parsed, time))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_time_synchronization_takes_only_a_specific_date_and_time() {
        // 2026-10-05 is a Monday.
        let noon = (12, 0, 0, 0);
        let (date, time) = specific_date_time((2026, 10, 5, 1), noon).unwrap();
        assert_eq!(date_value(&date), (2026, 10, 5, 1));
        assert_eq!((time.hour, time.hundredths), (12, 0));
        for date in [
            (255, 10, 5, 1),    // unspecified year
            (2026, 255, 5, 1),  // unspecified month
            (2026, 13, 5, 1),   // odd months
            (2026, 10, 255, 1), // unspecified day
            (2026, 10, 32, 1),  // last day
            (2026, 2, 29, 7),   // no such day
            (2026, 10, 5, 255), // unspecified weekday
            (2026, 10, 5, 2),   // the wrong weekday
        ] {
            assert!(specific_date_time(date, noon).is_err(), "{date:?}");
        }
        for time in [
            (255, 0, 0, 0),
            (12, 255, 0, 0),
            (12, 0, 255, 0),
            (12, 0, 0, 255),
            (24, 0, 0, 0),
        ] {
            assert!(
                specific_date_time((2026, 10, 5, 1), time).is_err(),
                "{time:?}"
            );
        }
    }

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
