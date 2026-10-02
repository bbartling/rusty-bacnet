//! Calendar Date_List over the services (#996): each BACnetCalendarEntry
//! travels under its Clause 21 CHOICE tag in ReadProperty, WriteProperty,
//! WritePropertyMultiple, AddListElement, RemoveListElement and ReadRange.
//! Before, entries read as an application Date or Octet String and Date_List
//! refused every write.

use super::*;
use bacnet_objects::schedule::CalendarObject;
use bacnet_services::common::BACnetPropertyValue;
use bacnet_services::list_manipulation::ListElementRequest;
use bacnet_services::read_range::{RangeSpec, ReadRangeAck, ReadRangeRequest};
use bacnet_services::wpm::{WriteAccessSpecification, WritePropertyMultipleRequest};
use bacnet_types::constructed::{BACnetCalendarEntry, BACnetDateRange, BACnetWeekNDay};
use bacnet_types::primitives::Date;

const DATE_LIST: PropertyIdentifier = PropertyIdentifier::DATE_LIST;

/// date `[0]` holding four octets (0x0C): Monday 14 September 2026, as year
/// minus 1900, month, day and weekday.
const DATE: &[u8] = &[0x0C, 126, 9, 14, 1];
/// date-range `[1]`: opening tag 0x1E, two application Dates (0xA4), closing
/// tag 0x1F. Thursday 1 January to Thursday 31 December 2026.
const RANGE: &[u8] = &[0x1E, 0xA4, 126, 1, 1, 4, 0xA4, 126, 12, 31, 4, 0x1F];
/// weekNDay `[2]` holding three octets (0x2B): every Monday, with month and
/// week-of-month unspecified.
const MONDAYS: &[u8] = &[0x2B, 0xFF, 0xFF, 1];

fn date(year: u8, month: u8, day: u8, day_of_week: u8) -> Date {
    Date {
        year,
        month,
        day,
        day_of_week,
    }
}

/// The typed entries the three golden vectors stand for.
fn typed() -> [BACnetCalendarEntry; 3] {
    [
        BACnetCalendarEntry::Date(date(126, 9, 14, 1)),
        BACnetCalendarEntry::DateRange(BACnetDateRange {
            start_date: date(126, 1, 1, 4),
            end_date: date(126, 12, 31, 4),
        }),
        BACnetCalendarEntry::WeekNDay(BACnetWeekNDay {
            month: 0xFF,
            week_of_month: 0xFF,
            day_of_week: 1,
        }),
    ]
}

/// A database holding Calendar 1 with the given entries.
fn calendar_db(entries: &[BACnetCalendarEntry]) -> (ObjectDatabase, ObjectIdentifier) {
    let mut calendar = CalendarObject::new(1, "CAL-1").unwrap();
    for entry in entries {
        calendar.add_date_entry(entry.clone()).unwrap();
    }
    let oid = calendar.object_identifier();
    let mut db = ObjectDatabase::new();
    db.add(Box::new(calendar)).unwrap();
    (db, oid)
}

/// Date_List as a ReadProperty ACK carries it.
fn read_wire(db: &ObjectDatabase, oid: ObjectIdentifier) -> Vec<u8> {
    let mut request = BytesMut::new();
    ReadPropertyRequest {
        object_identifier: oid,
        property_identifier: DATE_LIST,
        property_array_index: None,
    }
    .encode(&mut request);
    let mut response = BytesMut::new();
    handle_read_property(db, &request, &mut response).unwrap();
    ReadPropertyACK::decode(&response).unwrap().property_value
}

fn write(db: &mut ObjectDatabase, oid: ObjectIdentifier, value: &[u8]) -> Result<(), Error> {
    let mut request = BytesMut::new();
    WritePropertyRequest {
        object_identifier: oid,
        property_identifier: DATE_LIST,
        property_array_index: None,
        property_value: value.to_vec(),
        priority: None,
    }
    .encode(&mut request)
    .unwrap();
    handle_write_property(db, &request).map(|_| ())
}

fn edit(
    db: &mut ObjectDatabase,
    oid: ObjectIdentifier,
    elements: &[u8],
    remove: bool,
) -> Result<(), Error> {
    let mut request = BytesMut::new();
    ListElementRequest {
        object_identifier: oid,
        property_identifier: DATE_LIST,
        property_array_index: None,
        list_of_elements: elements.to_vec(),
    }
    .encode(&mut request)
    .unwrap();
    if remove {
        handle_remove_list_element(db, &request)
    } else {
        handle_add_list_element(db, &request)
    }
}

fn assert_property_error(result: Result<(), Error>, expected: ErrorCode, context: &str) {
    match result {
        Err(Error::Protocol { class, code }) => {
            assert_eq!(class, ErrorClass::PROPERTY.to_raw() as u32, "{context}");
            assert_eq!(code, expected.to_raw() as u32, "{context}: {expected:?}");
        }
        other => panic!("{context}: expected PROPERTY/{expected:?}, got {other:?}"),
    }
}

#[test]
fn date_list_reads_each_entry_under_its_choice_tag() {
    let (db, oid) = calendar_db(&typed());
    let wire = read_wire(&db, oid);
    assert_eq!(wire, [DATE, RANGE, MONDAYS].concat());
    assert_eq!(
        bacnet_encoding::constructed::decode_calendar_entry_list(&wire).unwrap(),
        typed()
    );
}

#[test]
fn date_list_write_property_takes_every_choice() {
    let (mut db, oid) = calendar_db(&[]);
    let all = [DATE, RANGE, MONDAYS].concat();
    write(&mut db, oid, &all).unwrap();
    assert_eq!(read_wire(&db, oid), all);
    // One entry, then the empty list.
    write(&mut db, oid, RANGE).unwrap();
    assert_eq!(read_wire(&db, oid), RANGE);
    write(&mut db, oid, &[]).unwrap();
    assert!(read_wire(&db, oid).is_empty());
}

#[test]
fn date_list_write_property_refuses_other_datatypes_and_bad_encodings() {
    let (mut db, oid) = calendar_db(&typed());
    let before = read_wire(&db, oid);
    for (what, value, expected) in [
        // The application-tagged forms Date_List used to read as.
        (
            "application Date",
            &[0xA4, 126, 9, 14, 1][..],
            ErrorCode::INVALID_DATA_TYPE,
        ),
        (
            "application Octet String",
            &[0x63, 0xFF, 0xFF, 1],
            ErrorCode::INVALID_DATA_TYPE,
        ),
        (
            "a good entry, then unknown alternative [3]",
            &[0x0C, 126, 9, 14, 1, 0x3B, 0xFF, 0xFF, 1],
            ErrorCode::INVALID_DATA_TYPE,
        ),
        (
            "date [0] with three octets",
            &[0x0B, 126, 9, 14],
            ErrorCode::INVALID_DATA_ENCODING,
        ),
        (
            "weekNDay [2] with four octets",
            &[0x2C, 0xFF, 0xFF, 1, 0],
            ErrorCode::INVALID_DATA_ENCODING,
        ),
        (
            "date-range [1] holding context-tagged dates",
            &[0x1E, 0x0C, 126, 1, 1, 4, 0x1C, 126, 12, 31, 4, 0x1F],
            ErrorCode::INVALID_DATA_ENCODING,
        ),
    ] {
        assert_property_error(write(&mut db, oid, value), expected, what);
        assert_eq!(read_wire(&db, oid), before, "{what} changed Date_List");
    }
}

#[test]
fn date_list_write_property_multiple_takes_entries_and_keeps_the_prefix() {
    let (mut db, oid) = calendar_db(&[]);
    let property = |value: &[u8]| BACnetPropertyValue {
        property_identifier: DATE_LIST,
        property_array_index: None,
        value: value.to_vec(),
        priority: None,
    };
    let mut request = BytesMut::new();
    WritePropertyMultipleRequest {
        list_of_write_access_specs: vec![WriteAccessSpecification {
            object_identifier: oid,
            list_of_properties: vec![
                property(&[RANGE, MONDAYS].concat()),
                property(&[0xA4, 126, 9, 14, 1]),
            ],
        }],
    }
    .encode(&mut request)
    .unwrap();
    assert_property_error(
        handle_write_property_multiple(&mut db, &request).map(|_| ()),
        ErrorCode::INVALID_DATA_TYPE,
        "second write carries an application Date",
    );
    assert_eq!(read_wire(&db, oid), [RANGE, MONDAYS].concat());
}

#[test]
fn date_list_add_and_remove_list_element_match_entries_by_choice() {
    let (mut db, oid) = calendar_db(&typed()[..1]);
    // DATE is present already, so the list gains RANGE and MONDAYS only.
    edit(&mut db, oid, &[RANGE, DATE, MONDAYS].concat(), false).unwrap();
    assert_eq!(read_wire(&db, oid), [DATE, RANGE, MONDAYS].concat());
    edit(&mut db, oid, &[MONDAYS, DATE].concat(), true).unwrap();
    assert_eq!(read_wire(&db, oid), RANGE);
    // A date range of one day matches no stored entry: the request fails at
    // that element and RANGE stays (#1027).
    let one_day = [0x1E, 0xA4, 126, 9, 14, 1, 0xA4, 126, 9, 14, 1, 0x1F];
    assert_eq!(
        list_refusal(edit(&mut db, oid, &[RANGE, &one_day[..]].concat(), true)),
        (ErrorClass::SERVICES, ErrorCode::LIST_ELEMENT_NOT_FOUND, 2)
    );
    assert_eq!(read_wire(&db, oid), RANGE);
    edit(&mut db, oid, RANGE, true).unwrap();
    assert!(read_wire(&db, oid).is_empty());
}

#[test]
fn date_list_list_services_refuse_bad_entries_without_partial_commit() {
    // The list services decode elements with the calendar-entry codec, so an
    // element that isn't a well-formed entry is refused as the wrong datatype
    // by either service, as for the other list codecs, and nothing changes.
    let (mut db, oid) = calendar_db(&typed()[..2]);
    let before = read_wire(&db, oid);
    for (what, bad) in [
        ("an application Date", &[0xA4, 126, 9, 14, 1][..]),
        ("an application Octet String", &[0x63, 0xFF, 0xFF, 1]),
        ("unknown alternative [3]", &[0x3B, 0xFF, 0xFF, 1]),
        ("a date [0] with three octets", &[0x0B, 126, 9, 14]),
        (
            "a date-range [1] holding context-tagged dates",
            &[0x1E, 0x0C, 126, 1, 1, 4, 0x1C, 126, 12, 31, 4, 0x1F],
        ),
    ] {
        for (remove, good) in [(false, MONDAYS), (true, DATE)] {
            let elements = [good, bad].concat();
            assert_eq!(
                list_refusal(edit(&mut db, oid, &elements, remove)),
                (ErrorClass::PROPERTY, ErrorCode::INVALID_DATA_TYPE, 2),
                "{what} (remove: {remove})"
            );
            assert_eq!(read_wire(&db, oid), before, "{what} changed Date_List");
        }
    }
}

#[test]
fn date_list_add_list_element_past_the_cap_is_no_space_to_add() {
    let monday = typed()[2].clone();
    let (mut db, oid) = calendar_db(&vec![monday; 1024]);
    let before = read_wire(&db, oid);
    // MONDAYS is present, so DATE is the element that does not fit.
    assert_eq!(
        list_refusal(edit(&mut db, oid, &[MONDAYS, DATE].concat(), false)),
        (
            ErrorClass::RESOURCES,
            ErrorCode::NO_SPACE_TO_ADD_LIST_ELEMENT,
            2
        )
    );
    assert_eq!(read_wire(&db, oid), before);
}

#[test]
fn date_list_read_range_addresses_entries_by_position() {
    let (db, oid) = calendar_db(&typed());
    let mut request = BytesMut::new();
    ReadRangeRequest {
        object_identifier: oid,
        property_identifier: DATE_LIST,
        property_array_index: None,
        range: Some(RangeSpec::ByPosition {
            reference_index: 2,
            count: 2,
        }),
    }
    .encode(&mut request)
    .unwrap();
    let mut response = BytesMut::new();
    handle_read_range(&db, &request, &mut response).unwrap();
    let ack = ReadRangeAck::decode(&response).unwrap();
    assert_eq!(ack.item_count, 2);
    assert_eq!(ack.item_data, [RANGE, MONDAYS].concat());
    assert_eq!(ack.result_flags, (false, true, false));
}

#[test]
fn date_list_refuses_out_of_range_entries_over_every_write_service() {
    // #1029: these entries decoded and were stored as written. Each is well
    // formed but holds an octet outside its Clause 21 range.
    let (mut db, oid) = calendar_db(&typed()[..2]);
    let before = read_wire(&db, oid);
    for (what, bad) in [
        ("date month 15", &[0x0C, 126, 15, 14, 0xFF][..]),
        ("date weekday 8", &[0x0C, 0xFF, 0xFF, 0xFF, 8]),
        (
            "date-range start without a year",
            &[0x1E, 0xA4, 0xFF, 1, 1, 4, 0xA4, 126, 12, 31, 4, 0x1F],
        ),
        (
            "date-range end on 30 February",
            &[0x1E, 0xA4, 126, 1, 1, 4, 0xA4, 126, 2, 30, 1, 0x1F],
        ),
        ("weekNDay week-of-month 10", &[0x2B, 0xFF, 10, 0xFF]),
        ("weekNDay month 0", &[0x2B, 0, 0xFF, 1]),
    ] {
        // A good entry ahead of the bad one does not save the request.
        let elements = [MONDAYS, bad].concat();
        assert_property_error(
            write(&mut db, oid, &elements),
            ErrorCode::VALUE_OUT_OF_RANGE,
            &format!("WriteProperty: {what}"),
        );
        let mut request = BytesMut::new();
        WritePropertyMultipleRequest {
            list_of_write_access_specs: vec![WriteAccessSpecification {
                object_identifier: oid,
                list_of_properties: vec![BACnetPropertyValue {
                    property_identifier: DATE_LIST,
                    property_array_index: None,
                    value: elements.clone(),
                    priority: None,
                }],
            }],
        }
        .encode(&mut request)
        .unwrap();
        assert_property_error(
            handle_write_property_multiple(&mut db, &request).map(|_| ()),
            ErrorCode::VALUE_OUT_OF_RANGE,
            &format!("WritePropertyMultiple: {what}"),
        );
        // AddListElement names the offending entry, the second, though the
        // first is the one the list would gain first.
        assert_eq!(
            list_refusal(edit(&mut db, oid, &elements, false)),
            (ErrorClass::PROPERTY, ErrorCode::VALUE_OUT_OF_RANGE, 2),
            "AddListElement: {what}"
        );
        // RemoveListElement has no VALUE_OUT_OF_RANGE (Clause 15.2.1.3.1).
        // No stored entry is ever out of range, so the entry is not found and
        // DATE ahead of it stays.
        assert_eq!(
            list_refusal(edit(&mut db, oid, &[DATE, bad].concat(), true)),
            (ErrorClass::SERVICES, ErrorCode::LIST_ELEMENT_NOT_FOUND, 2),
            "RemoveListElement: {what}"
        );
        assert_eq!(read_wire(&db, oid), before, "{what} changed Date_List");
    }
}
