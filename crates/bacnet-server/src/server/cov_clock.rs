use bacnet_objects::database::ObjectDatabase;
use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::primitives::{Date, ObjectIdentifier, PropertyValue, Time};
use std::time::{Duration, Instant};

pub(crate) fn device_utc_offset(db: &ObjectDatabase, device_oid: &ObjectIdentifier) -> i32 {
    db.get(device_oid)
        .and_then(|device| {
            device
                .read_property(PropertyIdentifier::UTC_OFFSET, None)
                .ok()
        })
        .and_then(|value| match value {
            PropertyValue::Signed(minutes) => Some(minutes),
            _ => None,
        })
        .unwrap_or(0)
}

pub(crate) fn cov_multiple_time_remaining(expires_at: Option<Instant>) -> u32 {
    expires_at.map_or(0, |expires_at| {
        u32::try_from(
            expires_at
                .saturating_duration_since(Instant::now())
                .as_secs(),
        )
        .unwrap_or(u32::MAX)
    })
}

/// Convert a UTC duration since the Unix epoch to local BACnet Date and Time.
///
/// COVNotificationMultiple carries an optional BACnetDateTime at the request
/// level and an optional primitive Time for each timestamped value. Keeping
/// both values on the same conversion path prevents them from disagreeing at
/// a day boundary. BACnet `UTC_Offset` is positive west of UTC and is
/// subtracted from UTC to obtain local standard time.
pub(crate) fn cov_multiple_datetime(elapsed: Duration, utc_offset_minutes: i32) -> (Date, Time) {
    let total_secs = elapsed
        .as_secs()
        .saturating_add_signed(-i64::from(utc_offset_minutes) * 60);
    let days_since_epoch = (total_secs / 86_400) as i64;
    let seconds_today = total_secs % 86_400;

    // Howard Hinnant's civil-from-days algorithm. The input epoch is
    // 1970-01-01; 719_468 shifts it to the algorithm's civil epoch.
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);

    let date = Date {
        year: u8::try_from(year - 1900).unwrap_or(Date::UNSPECIFIED),
        month: month as u8,
        day: day as u8,
        day_of_week: ((days_since_epoch + 3).rem_euclid(7) + 1) as u8,
    };
    let time = Time {
        hour: (seconds_today / 3_600) as u8,
        minute: ((seconds_today % 3_600) / 60) as u8,
        second: (seconds_today % 60) as u8,
        hundredths: (elapsed.subsec_millis() / 10) as u8,
    };

    (date, time)
}
