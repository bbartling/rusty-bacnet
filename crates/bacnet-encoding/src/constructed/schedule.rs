//! Clause 21 codecs for the Schedule object's constructed properties
//! (Clause 12.24): Weekly_Schedule and Exception_Schedule.
//!
//! - `BACnetTimeValue` is a SEQUENCE of two untagged members, so it is an
//!   application-tagged Time followed by one application-tagged primitive
//!   value, with no frame. [`BACnetTimeValue::value`] holds that value's raw
//!   bytes, tag included.
//! - `BACnetDailySchedule` is a SEQUENCE with one member, day-schedule `[0]`,
//!   a SEQUENCE OF `BACnetTimeValue`: an opening/closing `[0]` pair around the
//!   time-values. Weekly_Schedule is a BACnetARRAY\[7\] of them, Monday first.
//! - `BACnetSpecialEvent` is three members with no outer frame:
//!
//! | Member              | Tag          | Encoding                                         |
//! |---------------------|--------------|--------------------------------------------------|
//! | period              | (untagged)   | CHOICE: calendar-entry `[0]` or calendar-reference `[1]` |
//! | list-of-time-values | `[2]`        | opening/closing pair around the time-values      |
//! | event-priority      | `[3]`        | primitive Unsigned, 1 through 16                 |
//!
//! The calendar-entry alternative wraps a `BACnetCalendarEntry`, itself a
//! CHOICE, so it is an opening/closing `[0]` pair around the entry's own
//! tagged encoding (see [`super::calendar`]). The calendar-reference
//! alternative is a primitive `[1]` Calendar object identifier.
//! Exception_Schedule is a BACnetARRAY of special events, concatenated when
//! read whole.

use bacnet_types::constructed::{BACnetSpecialEvent, BACnetTimeValue, SpecialEventPeriod};
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, Time};
use bytes::BytesMut;

use super::calendar::{decode_calendar_entry, encode_calendar_entry};
use super::{decode_ctx_unsigned, expect_closing, expect_opening, MAX_FRAMED_ITEMS};
use crate::primitives;
use crate::tags::{self, TagClass};

/// Encode one `BACnetTimeValue`: the application-tagged Time, then the raw
/// application-tagged value bytes.
pub fn encode_time_value(buf: &mut BytesMut, time_value: &BACnetTimeValue) {
    primitives::encode_app_time(buf, &time_value.time);
    buf.extend_from_slice(&time_value.value);
}

/// Decode one `BACnetTimeValue` at `offset`.
///
/// The value must be a single application-tagged primitive; it is kept as its
/// raw bytes. Returns the time-value and the offset just past it.
pub fn decode_time_value(data: &[u8], offset: usize) -> Result<(BACnetTimeValue, usize), Error> {
    let (tag, content) = tags::decode_tag(data, offset)?;
    if tag.class != TagClass::Application || tag.number != tags::app_tag::TIME || tag.length != 4 {
        return Err(Error::decoding(
            offset,
            "time-value: expected an application-tagged Time (4 octets)",
        ));
    }
    let value_start = content + 4;
    if value_start > data.len() {
        return Err(Error::buffer_too_short(value_start, data.len()));
    }
    let time = Time::decode(&data[content..value_start])?;

    let (tag, content) = tags::decode_tag(data, value_start)?;
    if tag.class != TagClass::Application {
        return Err(Error::decoding(
            value_start,
            format!(
                "time-value: expected an application-tagged value, got context tag [{}]",
                tag.number
            ),
        ));
    }
    // An application Boolean carries its value in the tag octet and has no
    // content octets; every other primitive's content length is the tag length.
    let content_len = if tag.number == tags::app_tag::BOOLEAN {
        0
    } else {
        tag.length as usize
    };
    let value_end = content
        .checked_add(content_len)
        .ok_or_else(|| Error::decoding(content, "time-value: value length overflow"))?;
    if value_end > data.len() {
        return Err(Error::buffer_too_short(value_end, data.len()));
    }
    Ok((
        BACnetTimeValue {
            time,
            value: data[value_start..value_end].to_vec(),
        },
        value_end,
    ))
}

/// Encode a SEQUENCE OF `BACnetTimeValue` inside an opening/closing `tag` pair.
fn encode_time_values(buf: &mut BytesMut, tag: u8, time_values: &[BACnetTimeValue]) {
    tags::encode_opening_tag(buf, tag);
    for time_value in time_values {
        encode_time_value(buf, time_value);
    }
    tags::encode_closing_tag(buf, tag);
}

/// Decode a SEQUENCE OF `BACnetTimeValue` framed by an opening/closing `tag`
/// pair at `offset`; returns the time-values and the offset past the closing tag.
fn decode_time_values(
    data: &[u8],
    offset: usize,
    tag: u8,
    what: &str,
) -> Result<(Vec<BACnetTimeValue>, usize), Error> {
    let mut pos = expect_opening(data, offset, tag, what)?;
    let mut time_values = Vec::new();
    loop {
        let (peek, _) = tags::decode_tag(data, pos)?;
        if peek.is_closing_tag(tag) {
            return Ok((time_values, expect_closing(data, pos, tag, what)?));
        }
        if time_values.len() >= MAX_FRAMED_ITEMS {
            return Err(Error::decoding(
                pos,
                format!("{what}: time-values exceed item limit"),
            ));
        }
        let (time_value, next) = decode_time_value(data, pos)?;
        time_values.push(time_value);
        pos = next;
    }
}

/// Encode the period CHOICE of a `BACnetSpecialEvent`.
pub fn encode_special_event_period(buf: &mut BytesMut, period: &SpecialEventPeriod) {
    match period {
        SpecialEventPeriod::CalendarEntry(entry) => {
            tags::encode_opening_tag(buf, 0);
            encode_calendar_entry(buf, entry);
            tags::encode_closing_tag(buf, 0);
        }
        SpecialEventPeriod::CalendarReference(oid) => primitives::encode_ctx_object_id(buf, 1, oid),
    }
}

/// Decode the period CHOICE of a `BACnetSpecialEvent` at `offset`.
pub fn decode_special_event_period(
    data: &[u8],
    offset: usize,
) -> Result<(SpecialEventPeriod, usize), Error> {
    let (tag, content) = tags::decode_tag(data, offset)?;
    if tag.is_opening_tag(0) {
        let (entry, after) = decode_calendar_entry(data, content)?;
        let end = expect_closing(data, after, 0, "special event calendar-entry")?;
        return Ok((SpecialEventPeriod::CalendarEntry(entry), end));
    }
    if tag.is_context(1) {
        if tag.length != 4 {
            return Err(Error::decoding(
                offset,
                format!(
                    "special event calendar-reference [1]: expected 4 content octets, got {}",
                    tag.length
                ),
            ));
        }
        let end = content + 4;
        if end > data.len() {
            return Err(Error::buffer_too_short(end, data.len()));
        }
        let oid = ObjectIdentifier::decode(&data[content..end])?;
        return Ok((SpecialEventPeriod::CalendarReference(oid), end));
    }
    Err(Error::decoding(
        offset,
        "special event period requires calendar-entry [0] or calendar-reference [1]",
    ))
}

/// Encode one `BACnetSpecialEvent`.
pub fn encode_special_event(buf: &mut BytesMut, event: &BACnetSpecialEvent) {
    encode_special_event_period(buf, &event.period);
    encode_time_values(buf, 2, &event.list_of_time_values);
    primitives::encode_ctx_unsigned(buf, 3, u64::from(event.event_priority));
}

/// Decode one `BACnetSpecialEvent` at `offset`.
///
/// Rejects an event-priority outside 1 through 16, the range Clause 21 gives
/// the member. Returns the event and the offset just past it.
pub fn decode_special_event(
    data: &[u8],
    offset: usize,
) -> Result<(BACnetSpecialEvent, usize), Error> {
    let (period, pos) = decode_special_event_period(data, offset)?;
    let (list_of_time_values, pos) =
        decode_time_values(data, pos, 2, "special event list-of-time-values")?;
    let (priority, end) = decode_ctx_unsigned(data, pos, 3, "special event event-priority")?;
    if !(1..=16).contains(&priority) {
        return Err(Error::decoding(
            pos,
            format!("special event event-priority {priority} outside 1..=16"),
        ));
    }
    Ok((
        BACnetSpecialEvent {
            period,
            list_of_time_values,
            event_priority: priority as u8,
        },
        end,
    ))
}

/// Encode one `BACnetDailySchedule`: its time-values inside `[0]`.
pub fn encode_daily_schedule(buf: &mut BytesMut, time_values: &[BACnetTimeValue]) {
    encode_time_values(buf, 0, time_values);
}

/// Decode one `BACnetDailySchedule` at `offset`; returns its time-values and
/// the offset just past the closing `[0]`.
pub fn decode_daily_schedule(
    data: &[u8],
    offset: usize,
) -> Result<(Vec<BACnetTimeValue>, usize), Error> {
    decode_time_values(data, offset, 0, "daily schedule")
}

/// Encode a whole Weekly_Schedule: seven daily schedules, Monday first.
pub fn encode_weekly_schedule(buf: &mut BytesMut, days: &[Vec<BACnetTimeValue>; 7]) {
    for day in days {
        encode_daily_schedule(buf, day);
    }
}

/// Decode a whole Weekly_Schedule.
///
/// The data must hold exactly seven daily schedules and nothing after them:
/// the property is a fixed-size BACnetARRAY\[7\].
pub fn decode_weekly_schedule(data: &[u8]) -> Result<[Vec<BACnetTimeValue>; 7], Error> {
    let mut days: [Vec<BACnetTimeValue>; 7] = Default::default();
    let mut pos = 0;
    for (index, day) in days.iter_mut().enumerate() {
        let (time_values, next) = decode_daily_schedule(data, pos)
            .map_err(|e| Error::decoding(pos, format!("weekly schedule day {index}: {e}")))?;
        *day = time_values;
        pos = next;
    }
    if pos != data.len() {
        return Err(Error::decoding(
            pos,
            format!(
                "weekly schedule: {} trailing byte(s) after 7 daily schedules",
                data.len() - pos
            ),
        ));
    }
    Ok(days)
}

/// Encode a whole Exception_Schedule: the special events, concatenated.
pub fn encode_exception_schedule(buf: &mut BytesMut, events: &[BACnetSpecialEvent]) {
    for event in events {
        encode_special_event(buf, event);
    }
}

/// Decode a whole Exception_Schedule: zero or more special events, back to
/// back, with every byte belonging to one.
pub fn decode_exception_schedule(data: &[u8]) -> Result<Vec<BACnetSpecialEvent>, Error> {
    let mut events = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        if events.len() >= MAX_FRAMED_ITEMS {
            return Err(Error::decoding(
                pos,
                "exception schedule exceeds item limit",
            ));
        }
        let (event, next) = decode_special_event(data, pos).map_err(|e| {
            Error::decoding(
                pos,
                format!("exception schedule entry {}: {e}", events.len()),
            )
        })?;
        events.push(event);
        pos = next;
    }
    Ok(events)
}
