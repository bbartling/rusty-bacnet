//! Calendar object tests: Present_Value and the Date_List wire form (#996).

use super::*;
use bacnet_types::constructed::{BACnetDateRange, BACnetWeekNDay};

const DATE_LIST: PropertyIdentifier = PropertyIdentifier::DATE_LIST;

fn app(bytes: &[u8]) -> PropertyValue {
    PropertyValue::ApplicationData(bytes.to_vec())
}

fn monday_14_sep_2026() -> Date {
    Date {
        year: 126,
        month: 9,
        day: 14,
        day_of_week: 1,
    }
}

/// One entry per CHOICE alternative and its golden encoding, worked out from
/// the Clause 20.2.1 tag rules: date `[0]` holding four octets is 0x0C;
/// date-range `[1]` is opening tag 0x1E, two application Dates (0xA4 each)
/// and closing tag 0x1F; weekNDay `[2]` holding three octets is 0x2B.
fn entries_and_wire() -> Vec<(BACnetCalendarEntry, &'static [u8])> {
    let date = monday_14_sep_2026();
    vec![
        (BACnetCalendarEntry::Date(date), &[0x0C, 126, 9, 14, 1]),
        (
            BACnetCalendarEntry::DateRange(BACnetDateRange {
                start_date: date,
                end_date: date,
            }),
            &[0x1E, 0xA4, 126, 9, 14, 1, 0xA4, 126, 9, 14, 1, 0x1F],
        ),
        // Every Monday: month and week-of-month unspecified.
        (
            BACnetCalendarEntry::WeekNDay(BACnetWeekNDay {
                month: BACnetWeekNDay::ANY,
                week_of_month: BACnetWeekNDay::ANY,
                day_of_week: 1,
            }),
            &[0x2B, 0xFF, 0xFF, 1],
        ),
    ]
}

fn wire_list() -> PropertyValue {
    PropertyValue::List(entries_and_wire().iter().map(|(_, w)| app(w)).collect())
}

fn configured() -> CalendarObject {
    let mut cal = CalendarObject::new(1, "CAL-1").unwrap();
    for (entry, _) in entries_and_wire() {
        cal.add_date_entry(entry);
    }
    cal
}

fn assert_error(result: Result<(), Error>, class: ErrorClass, code: ErrorCode, what: &str) {
    match result {
        Err(Error::Protocol { class: c, code: e }) => {
            assert_eq!(c, class.to_raw() as u32, "{what}");
            assert_eq!(e, code.to_raw() as u32, "{what}: expected {code:?}");
        }
        other => panic!("{what}: expected {class:?}/{code:?}, got {other:?}"),
    }
}

#[test]
fn calendar_read_present_value_default() {
    let cal = CalendarObject::new(1, "CAL-1").unwrap();
    let val = cal
        .read_property(PropertyIdentifier::PRESENT_VALUE, None)
        .unwrap();
    assert_eq!(val, PropertyValue::Boolean(false));
}

#[test]
fn calendar_set_present_value() {
    let mut cal = CalendarObject::new(1, "CAL-1").unwrap();
    cal.set_present_value(true);
    let val = cal
        .read_property(PropertyIdentifier::PRESENT_VALUE, None)
        .unwrap();
    assert_eq!(val, PropertyValue::Boolean(true));
}

#[test]
fn calendar_write_present_value_denied() {
    let mut cal = CalendarObject::new(1, "CAL-1").unwrap();
    let result = cal.write_property(
        PropertyIdentifier::PRESENT_VALUE,
        None,
        PropertyValue::Boolean(true),
        None,
    );
    assert!(result.is_err());
}

#[test]
fn calendar_property_list_contains_date_list() {
    let cal = CalendarObject::new(1, "CAL-1").unwrap();
    assert!(cal.property_list().contains(&DATE_LIST));
    assert!(!cal.is_array_property(DATE_LIST));
}

#[test]
fn calendar_date_list_empty_by_default() {
    let cal = CalendarObject::new(1, "CAL-1").unwrap();
    assert_eq!(
        cal.read_property(DATE_LIST, None).unwrap(),
        PropertyValue::List(vec![])
    );
    assert!(cal.date_list().is_empty());
}

#[test]
fn calendar_date_list_reads_each_entry_under_its_choice_tag() {
    // #996: entries used to read as an application Date or Octet String.
    let mut cal = configured();
    // Direct reads ignore the index; the service handlers reject list indexing.
    for index in [None, Some(0), Some(1), Some(u32::MAX)] {
        assert_eq!(cal.read_property(DATE_LIST, index).unwrap(), wire_list());
    }
    let entries: Vec<_> = entries_and_wire().into_iter().map(|(e, _)| e).collect();
    assert_eq!(cal.date_list(), entries.as_slice());
    // Present_Value stays application-managed whatever Date_List holds.
    assert_eq!(
        cal.read_property(PropertyIdentifier::PRESENT_VALUE, None)
            .unwrap(),
        PropertyValue::Boolean(false)
    );
    cal.clear_date_list();
    assert_eq!(
        cal.read_property(DATE_LIST, None).unwrap(),
        PropertyValue::List(vec![])
    );
}

#[test]
fn calendar_date_list_write_accepts_every_choice_in_every_value_shape() {
    let all: Vec<u8> = entries_and_wire()
        .iter()
        .flat_map(|(_, w)| w.iter().copied())
        .collect();
    let entries: Vec<_> = entries_and_wire().into_iter().map(|(e, _)| e).collect();
    for (what, value, expected) in [
        // The service decoders hand over one element per entry ...
        ("one element per entry", wire_list(), entries.clone()),
        // ... or a single element when the payload holds one entry.
        (
            "one entry",
            app(&[0x2B, 0xFF, 0xFF, 1]),
            vec![entries[2].clone()],
        ),
        ("a pre-encoded list", app(&all), entries.clone()),
        ("an empty list", PropertyValue::List(vec![]), vec![]),
    ] {
        let mut cal = configured();
        cal.write_property(DATE_LIST, None, value, None)
            .unwrap_or_else(|e| panic!("{what}: {e:?}"));
        assert_eq!(cal.date_list(), expected.as_slice(), "{what}");
    }
    // A read value writes back unchanged.
    let mut cal = configured();
    let before = cal.read_property(DATE_LIST, None).unwrap();
    cal.write_property(DATE_LIST, None, before.clone(), None)
        .unwrap();
    assert_eq!(cal.read_property(DATE_LIST, None).unwrap(), before);
}

#[test]
fn calendar_date_list_write_refuses_other_datatypes() {
    let date = monday_14_sep_2026();
    for (what, value) in [
        // The projection Date_List used to read as (#996).
        ("Date", PropertyValue::Date(date)),
        (
            "Octet String",
            PropertyValue::OctetString(vec![255, 255, 1]),
        ),
        ("Null", PropertyValue::Null),
        ("Unsigned", PropertyValue::Unsigned(1)),
        (
            "list holding a Date",
            PropertyValue::List(vec![app(&[0x0C, 126, 9, 14, 1]), PropertyValue::Date(date)]),
        ),
        // Raw bytes whose leading tag is no calendar-entry choice.
        ("application-tagged Date bytes", app(&[0xA4, 126, 9, 14, 1])),
        ("unknown alternative [3]", app(&[0x3B, 0xFF, 0xFF, 1])),
    ] {
        let mut cal = configured();
        assert_error(
            cal.write_property(DATE_LIST, None, value, None),
            ErrorClass::PROPERTY,
            ErrorCode::INVALID_DATA_TYPE,
            what,
        );
        assert_eq!(cal.read_property(DATE_LIST, None).unwrap(), wire_list());
    }
}

#[test]
fn calendar_date_list_write_refuses_malformed_entries() {
    for (what, bytes) in [
        ("date [0] with three octets", &[0x0B, 126, 9, 14][..]),
        ("truncated date [0]", &[0x0C, 126, 9]),
        ("weekNDay [2] with four octets", &[0x2C, 0xFF, 0xFF, 1, 0]),
        (
            "date-range [1] never closed",
            &[0x1E, 0xA4, 126, 9, 14, 1, 0xA4, 126, 9, 14, 1],
        ),
        (
            "date-range [1] holding context-tagged dates",
            &[0x1E, 0x0C, 126, 9, 14, 1, 0x1C, 126, 9, 14, 1, 0x1F],
        ),
        (
            "date-range [1] as a primitive",
            &[0x1D, 8, 126, 9, 14, 1, 126, 9, 14, 1],
        ),
        (
            "a good entry, then a truncated one",
            &[0x2B, 0xFF, 0xFF, 1, 0x2B, 0xFF],
        ),
    ] {
        let mut cal = configured();
        assert_error(
            cal.write_property(DATE_LIST, None, app(bytes), None),
            ErrorClass::PROPERTY,
            ErrorCode::INVALID_DATA_ENCODING,
            what,
        );
        assert_eq!(cal.read_property(DATE_LIST, None).unwrap(), wire_list());
    }
}

#[test]
fn calendar_date_list_write_caps_the_entry_count() {
    let entry = app(&[0x2B, 0xFF, 0xFF, 1]);
    let mut cal = configured();
    cal.write_property(
        DATE_LIST,
        None,
        PropertyValue::List(vec![entry.clone(); date_list::MAX_DATE_LIST_ENTRIES]),
        None,
    )
    .unwrap();
    assert_eq!(cal.date_list().len(), date_list::MAX_DATE_LIST_ENTRIES);

    let mut cal = configured();
    assert_error(
        cal.write_property(
            DATE_LIST,
            None,
            PropertyValue::List(vec![entry; date_list::MAX_DATE_LIST_ENTRIES + 1]),
            None,
        ),
        ErrorClass::RESOURCES,
        ErrorCode::NO_SPACE_TO_WRITE_PROPERTY,
        "one entry over the cap",
    );
    assert_eq!(cal.read_property(DATE_LIST, None).unwrap(), wire_list());
}

#[test]
fn calendar_date_list_write_refuses_an_array_index() {
    let mut cal = configured();
    for index in [0, 1, u32::MAX] {
        assert_error(
            cal.write_property(DATE_LIST, Some(index), wire_list(), None),
            ErrorClass::PROPERTY,
            ErrorCode::PROPERTY_IS_NOT_AN_ARRAY,
            "indexed write",
        );
    }
    assert_eq!(cal.read_property(DATE_LIST, None).unwrap(), wire_list());
}
