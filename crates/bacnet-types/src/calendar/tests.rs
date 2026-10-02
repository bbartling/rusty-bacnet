//! Calendar matching tests (#1029, #1028): every Date pattern octet, both
//! date-range ends, every week-of-month form and the value ranges.

use super::*;

fn day(year: u16, month: u8, day: u8) -> SpecificDate {
    SpecificDate::new(year, month, day).unwrap()
}

fn date(year: u8, month: u8, day: u8, day_of_week: u8) -> Date {
    Date {
        year,
        month,
        day,
        day_of_week,
    }
}

const UNSPECIFIED: Date = Date {
    year: ANY,
    month: ANY,
    day: ANY,
    day_of_week: ANY,
};

fn range(start_date: Date, end_date: Date) -> BACnetDateRange {
    BACnetDateRange {
        start_date,
        end_date,
    }
}

fn wnd(month: u8, week_of_month: u8, day_of_week: u8) -> BACnetWeekNDay {
    BACnetWeekNDay {
        month,
        week_of_month,
        day_of_week,
    }
}

/// Every day of `year`-`month`.
fn month_days(year: u16, month: u8) -> impl Iterator<Item = SpecificDate> {
    (1..=days_in_month(year, month)).map(move |d| day(year, month, d))
}

#[test]
fn specific_date_exists_only_for_real_days_in_the_date_range() {
    assert!(SpecificDate::new(2024, 2, 29).is_some());
    assert!(SpecificDate::new(2000, 2, 29).is_some());
    assert!(SpecificDate::new(1900, 1, 1).is_some());
    assert!(SpecificDate::new(2154, 12, 31).is_some());
    for (year, month, d) in [
        (2026, 2, 29), // not a leap year
        (1900, 2, 29), // divisible by 100, not by 400
        (2026, 4, 31),
        (2026, 0, 1),
        (2026, 13, 1),
        (2026, 1, 0),
        (2026, 1, 32),
        (1899, 12, 31),
        (2155, 1, 1),
    ] {
        assert!(
            SpecificDate::new(year, month, d).is_none(),
            "{year}-{month}-{d}"
        );
    }
    // A Date names a day only with year, month and day specified and no
    // special values; its weekday octet is not consulted.
    assert_eq!(
        SpecificDate::from_date(&date(126, 9, 14, ANY)),
        Some(day(2026, 9, 14))
    );
    assert_eq!(
        SpecificDate::from_date(&date(126, 9, 14, 3)),
        Some(day(2026, 9, 14))
    );
    for pattern in [
        date(ANY, 9, 14, 1),
        date(126, ANY, 14, 1),
        date(126, 9, ANY, 1),
        date(126, 13, 14, 1),
        date(126, 14, 14, 1),
        date(126, 9, 32, 1),
        date(126, 9, 33, 1),
        date(126, 9, 34, 1),
        date(126, 2, 30, 1),
        UNSPECIFIED,
    ] {
        assert_eq!(SpecificDate::from_date(&pattern), None, "{pattern:?}");
    }
}

#[test]
fn weekday_is_monday_first_and_advances_one_per_day_over_every_date() {
    for (d, weekday) in [
        (day(1900, 1, 1), 1),
        (day(2000, 2, 29), 2),
        (day(2024, 2, 29), 4),
        (day(2026, 1, 1), 4),
        (day(2026, 9, 14), 1),
        (day(2026, 12, 25), 5),
        (day(2154, 12, 31), 2),
    ] {
        assert_eq!(d.weekday(), weekday, "{d:?}");
    }
    let mut expected = 1;
    let mut count = 0;
    for year in 1900..=2154 {
        for month in 1..=12 {
            for d in month_days(year, month) {
                assert_eq!(d.weekday(), expected, "{d:?}");
                assert_eq!(SpecificDate::from_date(&d.to_date()), Some(d));
                assert_eq!(d.to_date().day_of_week, expected);
                expected = expected % 7 + 1;
                count += 1;
            }
        }
    }
    // 255 years, 62 of them leap years.
    assert_eq!(count, 255 * 365 + 62);
}

#[test]
fn days_in_month_follows_the_gregorian_leap_rule() {
    assert_eq!(days_in_month(2026, 1), 31);
    assert_eq!(days_in_month(2026, 2), 28);
    assert_eq!(days_in_month(2024, 2), 29);
    assert_eq!(days_in_month(2000, 2), 29);
    assert_eq!(days_in_month(2100, 2), 28);
    assert_eq!(days_in_month(2026, 4), 30);
    assert_eq!(days_in_month(2026, 0), 0);
    assert_eq!(days_in_month(2026, 13), 0);
}

#[test]
fn date_pattern_matches_each_specified_octet_independently() {
    let friday_christmas = day(2026, 12, 25);
    for (what, pattern, expected) in [
        ("unspecified", UNSPECIFIED, true),
        ("exact date", date(126, 12, 25, 5), true),
        (
            "exact date, weekday unspecified",
            date(126, 12, 25, ANY),
            true,
        ),
        // Every specified octet must match, the weekday included.
        ("wrong weekday", date(126, 12, 25, 1), false),
        ("wrong year", date(125, 12, 25, ANY), false),
        ("any year's Christmas", date(ANY, 12, 25, ANY), true),
        ("any Friday", date(ANY, ANY, ANY, 5), true),
        ("any Monday", date(ANY, ANY, ANY, 1), false),
        ("any 25th", date(ANY, ANY, 25, ANY), true),
        ("2026, any day", date(126, ANY, ANY, ANY), true),
        ("even months", date(ANY, 14, 25, ANY), true),
        ("odd months", date(ANY, 13, 25, ANY), false),
        ("odd days", date(ANY, ANY, 33, ANY), true),
        ("even days", date(ANY, ANY, 34, ANY), false),
        ("last day of the month", date(ANY, ANY, 32, ANY), false),
    ] {
        assert_eq!(pattern.matches(friday_christmas), expected, "{what}");
    }
    // Day 32 is each month's own last day, leap Februaries included.
    let last = date(ANY, ANY, 32, ANY);
    for (d, expected) in [
        (day(2026, 2, 28), true),
        (day(2024, 2, 28), false),
        (day(2024, 2, 29), true),
        (day(2026, 4, 30), true),
        (day(2026, 1, 30), false),
        (day(2026, 1, 31), true),
    ] {
        assert_eq!(last.matches(d), expected, "{d:?}");
    }
    // Odd and even months and days split every date between them.
    for d in month_days(2026, 7).chain(month_days(2026, 8)) {
        let odd_month = d.month() % 2 == 1;
        let odd_day = d.day() % 2 == 1;
        assert_eq!(date(ANY, 13, ANY, ANY).matches(d), odd_month);
        assert_eq!(date(ANY, 14, ANY, ANY).matches(d), !odd_month);
        assert_eq!(date(ANY, ANY, 33, ANY).matches(d), odd_day);
        assert_eq!(date(ANY, ANY, 34, ANY).matches(d), !odd_day);
    }
}

#[test]
fn date_pattern_validity_follows_the_octet_ranges() {
    for valid in [
        UNSPECIFIED,
        date(0, 1, 1, 1),
        date(254, 12, 31, 7),
        date(126, 13, 33, ANY),
        date(126, 14, 34, ANY),
        date(ANY, ANY, 32, ANY),
    ] {
        assert!(valid.is_valid_pattern(), "{valid:?}");
    }
    for invalid in [
        date(126, 0, 1, 1),
        date(126, 15, 1, 1),
        date(126, 254, 1, 1),
        date(126, 1, 0, 1),
        date(126, 1, 35, 1),
        date(126, 1, 1, 0),
        date(126, 1, 1, 8),
    ] {
        assert!(!invalid.is_valid_pattern(), "{invalid:?}");
    }
}

#[test]
fn date_range_includes_both_ends_and_opens_on_unspecified_ends() {
    let start = date(126, 7, 1, 3);
    let end = date(126, 8, 31, 1);
    let summer = range(start, end);
    assert!(summer.is_valid());
    for (d, expected) in [
        (day(2026, 6, 30), false),
        (day(2026, 7, 1), true),
        (day(2026, 7, 31), true),
        (day(2026, 8, 31), true),
        (day(2026, 9, 1), false),
        (day(2025, 7, 15), false),
        (day(2027, 7, 15), false),
    ] {
        assert_eq!(summer.contains(d), expected, "{d:?}");
    }
    // An unspecified start is every date up to the end; an unspecified end
    // every date from the start; both unspecified, every date.
    let until = range(UNSPECIFIED, end);
    let from = range(start, UNSPECIFIED);
    let always = range(UNSPECIFIED, UNSPECIFIED);
    for (d, before_end, after_start) in [
        (day(1900, 1, 1), true, false),
        (day(2026, 7, 1), true, true),
        (day(2026, 8, 31), true, true),
        (day(2154, 12, 31), false, true),
    ] {
        assert_eq!(until.contains(d), before_end, "until {d:?}");
        assert_eq!(from.contains(d), after_start, "from {d:?}");
        assert!(always.contains(d), "always {d:?}");
    }
    // A reversed range is valid octet by octet and contains nothing.
    let reversed = range(end, start);
    assert!(reversed.is_valid());
    assert!(!reversed.contains(day(2026, 7, 15)));
    // The weekday octet may be unspecified or disagree with the date.
    let loose = range(date(126, 7, 1, ANY), date(126, 8, 31, 5));
    assert!(loose.is_valid());
    assert!(loose.contains(day(2026, 8, 31)));
}

#[test]
fn date_range_endpoint_is_a_specific_date_or_wholly_unspecified() {
    let good = date(126, 7, 1, 3);
    for (what, bad) in [
        ("year unspecified", date(ANY, 7, 1, 3)),
        ("month unspecified", date(126, ANY, 1, 3)),
        ("day unspecified", date(126, 7, ANY, 3)),
        ("odd months", date(126, 13, 1, 3)),
        ("even months", date(126, 14, 1, 3)),
        ("last day", date(126, 7, 32, 3)),
        ("odd days", date(126, 7, 33, 3)),
        ("even days", date(126, 7, 34, 3)),
        ("30 February", date(126, 2, 30, 1)),
        ("month 0", date(126, 0, 1, 3)),
        ("weekday 0", date(126, 7, 1, 0)),
        ("weekday 8", date(126, 7, 1, 8)),
        ("only the weekday", date(ANY, ANY, ANY, 3)),
    ] {
        for r in [range(bad, good), range(good, bad), range(bad, UNSPECIFIED)] {
            assert!(!r.is_valid(), "{what}: {r:?}");
            assert!(!r.contains(day(2026, 7, 1)), "{what}: {r:?}");
        }
    }
}

#[test]
fn week_n_day_weeks_one_to_five_are_seven_day_blocks_from_the_first() {
    for d in month_days(2026, 8) {
        let block = (d.day() - 1) / 7 + 1;
        for week in 1..=5 {
            assert_eq!(
                wnd(ANY, week, ANY).matches(d),
                week == block,
                "week {week} on {d:?}"
            );
        }
    }
    // Week 5 is days 29-31, which a non-leap February lacks.
    assert!(!month_days(2026, 2).any(|d| wnd(ANY, 5, ANY).matches(d)));
    assert!(wnd(ANY, 5, ANY).matches(day(2024, 2, 29)));
}

#[test]
fn week_n_day_weeks_six_to_nine_count_back_from_the_last_day() {
    // (year, month, first day of weeks 6, 7, 8 and 9).
    for (year, month, firsts) in [
        (2026, 1, [25, 18, 11, 4]), // 31 days
        (2026, 4, [24, 17, 10, 3]), // 30 days
        (2024, 2, [23, 16, 9, 2]),  // 29 days
        (2026, 2, [22, 15, 8, 1]),  // 28 days
    ] {
        for (week, first) in (6..=9).zip(firsts) {
            let matched: Vec<u8> = month_days(year, month)
                .filter(|&d| wnd(ANY, week, ANY).matches(d))
                .map(SpecificDate::day)
                .collect();
            assert_eq!(
                matched,
                (first..first + 7).collect::<Vec<u8>>(),
                "{year}-{month} week {week}"
            );
        }
    }
}

#[test]
fn week_n_day_combines_month_week_and_weekday() {
    // Last Monday of May, and the fourth Thursday of November, 2026.
    let last_monday_of_may = wnd(5, 6, 1);
    let fourth_thursday_of_november = wnd(11, 4, 4);
    for (entry, expected) in [
        (&last_monday_of_may, day(2026, 5, 25)),
        (&fourth_thursday_of_november, day(2026, 11, 26)),
    ] {
        let hits: Vec<_> = (1..=12)
            .flat_map(|m| month_days(2026, m))
            .filter(|&d| entry.matches(d))
            .collect();
        assert_eq!(hits, vec![expected], "{entry:?}");
    }
    // Every Monday all year: month and week-of-month unspecified.
    let mondays = wnd(ANY, ANY, 1);
    for d in (1..=12).flat_map(|m| month_days(2026, m)) {
        assert_eq!(mondays.matches(d), d.weekday() == 1, "{d:?}");
    }
    // Odd and even months.
    assert!(wnd(13, ANY, ANY).matches(day(2026, 7, 4)));
    assert!(!wnd(14, ANY, ANY).matches(day(2026, 7, 4)));
    assert!(wnd(14, ANY, ANY).matches(day(2026, 12, 25)));
    assert!(wnd(ANY, ANY, ANY).matches(day(2026, 12, 25)));
}

#[test]
fn week_n_day_validity_follows_the_octet_ranges() {
    for valid in [
        wnd(ANY, ANY, ANY),
        wnd(1, 1, 1),
        wnd(14, 9, 7),
        wnd(13, 6, ANY),
    ] {
        assert!(valid.is_valid(), "{valid:?}");
    }
    for invalid in [
        wnd(0, 1, 1),
        wnd(15, 1, 1),
        wnd(1, 0, 1),
        wnd(1, 10, 1),
        wnd(1, 1, 0),
        wnd(1, 1, 8),
    ] {
        assert!(!invalid.is_valid(), "{invalid:?}");
        // An out-of-range octet matches no day.
        assert!(
            !(1..=12)
                .flat_map(|m| month_days(2026, m))
                .any(|d| invalid.matches(d)),
            "{invalid:?}"
        );
    }
}

#[test]
fn calendar_entry_dispatches_to_its_choice() {
    let christmas = day(2026, 12, 25);
    let entries = [
        (BACnetCalendarEntry::Date(date(ANY, 12, 25, ANY)), true),
        (
            BACnetCalendarEntry::DateRange(range(date(126, 12, 24, 4), date(126, 12, 26, 6))),
            true,
        ),
        (BACnetCalendarEntry::WeekNDay(wnd(12, 4, 5)), true),
        (BACnetCalendarEntry::WeekNDay(wnd(12, 4, 4)), false),
    ];
    for (entry, expected) in &entries {
        assert!(entry.is_valid(), "{entry:?}");
        assert_eq!(entry.matches(christmas), *expected, "{entry:?}");
    }
    for invalid in [
        BACnetCalendarEntry::Date(date(126, 0, 25, ANY)),
        BACnetCalendarEntry::DateRange(range(date(ANY, 12, 24, 4), UNSPECIFIED)),
        BACnetCalendarEntry::WeekNDay(wnd(12, 10, 5)),
    ] {
        assert!(!invalid.is_valid(), "{invalid:?}");
    }
}

#[test]
fn time_is_specific_only_with_every_field_in_range() {
    let time = |hour, minute, second, hundredths| Time {
        hour,
        minute,
        second,
        hundredths,
    };
    assert!(time(0, 0, 0, 0).is_specific());
    assert!(time(23, 59, 59, 99).is_specific());
    for t in [
        time(24, 0, 0, 0),
        time(0, 60, 0, 0),
        time(0, 0, 60, 0),
        time(0, 0, 0, 100),
        time(ANY, 0, 0, 0),
        time(8, ANY, 0, 0),
    ] {
        assert!(!t.is_specific(), "{t:?}");
    }
}
