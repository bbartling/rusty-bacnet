//! `BACnetCalendarEntry` and `BACnetDateRange` (Clause 21) golden vectors and
//! rejections (#996).
//!
//! The vectors are worked out by hand from the Clause 20.2.1 tag rules: a tag
//! octet holds the tag number in its high nibble, then the class bit (set for
//! a context tag), then a three-bit length/value/type field holding a
//! primitive's length when it is 0 through 4, or 6 and 7 for an opening and a
//! closing tag. A Date is four octets (year minus 1900, month, day, weekday
//! with Monday as 1) and a BACnetWeekNDay three (month, week-of-month,
//! weekday); 0xFF leaves an octet unspecified.

use super::*;
use bacnet_types::constructed::{BACnetCalendarEntry, BACnetDateRange, BACnetWeekNDay};
use bacnet_types::primitives::Date;

fn date(year: u8, month: u8, day: u8, day_of_week: u8) -> Date {
    Date {
        year,
        month,
        day,
        day_of_week,
    }
}

fn any_date() -> Date {
    date(0xFF, 0xFF, 0xFF, 0xFF)
}

fn week_n_day(month: u8, week_of_month: u8, day_of_week: u8) -> BACnetWeekNDay {
    BACnetWeekNDay {
        month,
        week_of_month,
        day_of_week,
    }
}

fn encode(entry: &BACnetCalendarEntry) -> Vec<u8> {
    let mut buf = BytesMut::new();
    encode_calendar_entry(&mut buf, entry);
    buf.to_vec()
}

/// One golden vector per alternative, from `calendar_entry_golden_vectors`.
fn one_of_each() -> [(BACnetCalendarEntry, &'static [u8]); 3] {
    [
        (
            BACnetCalendarEntry::Date(date(126, 9, 14, 1)),
            &[0x0C, 126, 9, 14, 1],
        ),
        (
            BACnetCalendarEntry::DateRange(BACnetDateRange {
                start_date: date(126, 1, 1, 4),
                end_date: date(126, 12, 31, 4),
            }),
            &[0x1E, 0xA4, 126, 1, 1, 4, 0xA4, 126, 12, 31, 4, 0x1F],
        ),
        (
            BACnetCalendarEntry::WeekNDay(week_n_day(11, 4, 4)),
            &[0x2B, 11, 4, 4],
        ),
    ]
}

#[test]
fn calendar_entry_golden_vectors() {
    let cases: [(BACnetCalendarEntry, &[u8]); 6] = [
        // date [0]: context tag 0 holding four octets is 0x0C, then the Date.
        // Monday 14 September 2026.
        (
            BACnetCalendarEntry::Date(date(126, 9, 14, 1)),
            &[0x0C, 126, 9, 14, 1],
        ),
        // A date pattern: the 25th of any month of any year, any weekday.
        (
            BACnetCalendarEntry::Date(date(0xFF, 0xFF, 25, 0xFF)),
            &[0x0C, 0xFF, 0xFF, 25, 0xFF],
        ),
        // date-range [1] is constructed: opening tag 1 is 0x1E and closing
        // tag 1 is 0x1F. Inside, each Date carries application tag 10 with
        // length 4, 0xA4. Thursday 1 January to Thursday 31 December 2026.
        (
            BACnetCalendarEntry::DateRange(BACnetDateRange {
                start_date: date(126, 1, 1, 4),
                end_date: date(126, 12, 31, 4),
            }),
            &[0x1E, 0xA4, 126, 1, 1, 4, 0xA4, 126, 12, 31, 4, 0x1F],
        ),
        // A range with an unspecified start date (open-ended).
        (
            BACnetCalendarEntry::DateRange(BACnetDateRange {
                start_date: any_date(),
                end_date: date(126, 12, 31, 4),
            }),
            &[
                0x1E, 0xA4, 0xFF, 0xFF, 0xFF, 0xFF, 0xA4, 126, 12, 31, 4, 0x1F,
            ],
        ),
        // weekNDay [2]: context tag 2 holding three octets is 0x2B. November,
        // the days numbered 22 to 28 (week 4), Thursday.
        (
            BACnetCalendarEntry::WeekNDay(week_n_day(11, 4, 4)),
            &[0x2B, 11, 4, 4],
        ),
        // Every Monday: month and week-of-month unspecified.
        (
            BACnetCalendarEntry::WeekNDay(week_n_day(0xFF, 0xFF, 1)),
            &[0x2B, 0xFF, 0xFF, 1],
        ),
    ];
    for (entry, wire) in cases {
        assert_eq!(encode(&entry), wire, "{entry:?}");
        let (decoded, end) = decode_calendar_entry(wire, 0).unwrap();
        assert_eq!(decoded, entry);
        assert_eq!(end, wire.len());
    }
}

#[test]
fn calendar_entry_decodes_at_an_offset_and_stops_after_one_entry() {
    for (entry, wire) in one_of_each() {
        let mut framed = vec![0x21, 0x07];
        framed.extend_from_slice(wire);
        framed.extend_from_slice(&[0x2B, 0xFF, 0xFF, 7]);
        let (decoded, end) = decode_calendar_entry(&framed, 2).unwrap();
        assert_eq!(decoded, entry);
        assert_eq!(end, 2 + wire.len());
    }
}

#[test]
fn calendar_entry_list_is_the_concatenation_of_its_entries() {
    let entries: Vec<_> = one_of_each().into_iter().map(|(e, _)| e).collect();
    let wire: Vec<u8> = one_of_each()
        .iter()
        .flat_map(|(_, w)| w.iter().copied())
        .collect();
    let mut buf = BytesMut::new();
    encode_calendar_entry_list(&mut buf, &entries);
    assert_eq!(&buf[..], &wire[..]);
    assert_eq!(decode_calendar_entry_list(&wire).unwrap(), entries);

    let mut empty = BytesMut::new();
    encode_calendar_entry_list(&mut empty, &[]);
    assert!(empty.is_empty());
    assert!(decode_calendar_entry_list(&[]).unwrap().is_empty());
}

#[test]
fn unframed_date_range_is_two_application_dates() {
    let cases = [
        (
            BACnetDateRange {
                start_date: date(126, 1, 1, 4),
                end_date: date(126, 12, 31, 4),
            },
            [0xA4, 126, 1, 1, 4, 0xA4, 126, 12, 31, 4],
        ),
        // Both dates unspecified: the range covers every date.
        (
            BACnetDateRange {
                start_date: any_date(),
                end_date: any_date(),
            },
            [0xA4, 0xFF, 0xFF, 0xFF, 0xFF, 0xA4, 0xFF, 0xFF, 0xFF, 0xFF],
        ),
    ];
    for (range, wire) in cases {
        let mut buf = BytesMut::new();
        encode_date_range(&mut buf, &range);
        assert_eq!(&buf[..], &wire[..]);
        assert_eq!(decode_date_range(&wire, 0).unwrap(), (range, wire.len()));
    }
}

#[test]
fn calendar_entry_rejects_wrong_tags() {
    let cases: [(&str, &[u8]); 13] = [
        // The forms Date_List used to put on the wire (#996).
        ("application Date", &[0xA4, 126, 9, 14, 1]),
        ("application Octet String", &[0x63, 0xFF, 0xFF, 1]),
        ("unknown alternative [3]", &[0x3B, 0xFF, 0xFF, 1]),
        (
            "date [0] as an opening tag",
            &[0x0E, 0xA4, 126, 9, 14, 1, 0x0F],
        ),
        (
            "date-range [1] as an eight-octet primitive",
            &[0x1D, 8, 126, 1, 1, 4, 126, 12, 31, 4],
        ),
        (
            "weekNDay [2] as an opening tag",
            &[0x2E, 0x63, 11, 4, 4, 0x2F],
        ),
        ("a bare closing tag", &[0x1F]),
        (
            "date-range holding context-tagged dates",
            &[0x1E, 0x0C, 126, 1, 1, 4, 0x1C, 126, 12, 31, 4, 0x1F],
        ),
        (
            "date-range holding application Times",
            &[0x1E, 0xB4, 8, 0, 0, 0, 0xB4, 17, 0, 0, 0, 0x1F],
        ),
        (
            "date-range holding one date",
            &[0x1E, 0xA4, 126, 1, 1, 4, 0x1F],
        ),
        (
            "date-range holding three dates",
            &[
                0x1E, 0xA4, 126, 1, 1, 4, 0xA4, 126, 6, 1, 1, 0xA4, 126, 12, 31, 4, 0x1F,
            ],
        ),
        (
            "date-range closed by [2]",
            &[0x1E, 0xA4, 126, 1, 1, 4, 0xA4, 126, 12, 31, 4, 0x2F],
        ),
        (
            "date-range closed by [0]",
            &[0x1E, 0xA4, 126, 1, 1, 4, 0xA4, 126, 12, 31, 4, 0x0F],
        ),
    ];
    for (what, wire) in cases {
        assert!(decode_calendar_entry(wire, 0).is_err(), "{what} decoded");
        assert!(decode_calendar_entry_list(wire).is_err(), "{what} decoded");
    }
}

#[test]
fn calendar_entry_rejects_wrong_content_lengths() {
    let cases: [(&str, &[u8]); 7] = [
        ("date [0] with three octets", &[0x0B, 126, 9, 14]),
        ("date [0] with five octets", &[0x0D, 5, 126, 9, 14, 1, 0]),
        ("date [0] with no octets", &[0x08]),
        ("weekNDay [2] with two octets", &[0x2A, 11, 4]),
        ("weekNDay [2] with four octets", &[0x2C, 11, 4, 4, 0]),
        (
            "date-range start date with three octets",
            &[0x1E, 0xA3, 126, 1, 1, 0xA4, 126, 12, 31, 4, 0x1F],
        ),
        (
            "date-range end date with five octets",
            &[0x1E, 0xA4, 126, 1, 1, 4, 0xA5, 5, 126, 12, 31, 4, 0, 0x1F],
        ),
    ];
    for (what, wire) in cases {
        assert!(decode_calendar_entry(wire, 0).is_err(), "{what} decoded");
    }
}

#[test]
fn calendar_entry_rejects_truncated_data() {
    assert!(decode_calendar_entry(&[], 0).is_err());
    for (entry, wire) in one_of_each() {
        for cut in 1..wire.len() {
            assert!(
                decode_calendar_entry(&wire[..cut], 0).is_err(),
                "{entry:?} cut to {cut} octets decoded"
            );
            assert!(decode_calendar_entry_list(&wire[..cut]).is_err());
        }
    }
    for cut in 1..10 {
        let wire = [0xA4, 126, 1, 1, 4, 0xA4, 126, 12, 31, 4];
        assert!(decode_date_range(&wire[..cut], 0).is_err(), "cut to {cut}");
    }
}

#[test]
fn calendar_entry_list_rejects_a_bad_element_anywhere() {
    let good: &[u8] = &[0x2B, 0xFF, 0xFF, 1];
    let bad: &[u8] = &[0xA4, 126, 9, 14, 1];
    for wire in [
        [good, bad].concat(),
        [bad, good].concat(),
        [good, &good[..3]].concat(),
        [good, &[0x00]].concat(),
    ] {
        assert!(decode_calendar_entry_list(&wire).is_err(), "{wire:02x?}");
    }
}
