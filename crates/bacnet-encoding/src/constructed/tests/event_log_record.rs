use super::*;
use bacnet_types::bitstring::LogStatus;
use bacnet_types::constructed::{BACnetEventLogRecord, EventLogDatum};
use bacnet_types::primitives::{Date, Time};

fn record(log_datum: EventLogDatum) -> BACnetEventLogRecord {
    BACnetEventLogRecord {
        date: Date {
            year: 126,
            month: 8,
            day: 31,
            day_of_week: 1,
        },
        time: Time {
            hour: 14,
            minute: 25,
            second: 36,
            hundredths: 47,
        },
        log_datum,
    }
}

fn encoded(record: &BACnetEventLogRecord) -> Vec<u8> {
    let mut buf = BytesMut::new();
    encode_event_log_record(record, &mut buf).unwrap();
    buf.to_vec()
}

const TIMESTAMP: [u8; 12] = [
    0x0E, 0xA4, 0x7E, 0x08, 0x1F, 0x01, 0xB4, 0x0E, 0x19, 0x24, 0x2F, 0x0F,
];

/// The parameters of a short ConfirmedEventNotification request: process 1,
/// Device 1 reporting Analog Input 1 at sequence-number timestamp 5, class 0,
/// priority 100, CHANGE_OF_STATE, ALARM, no ack, NORMAL to OFFNORMAL.
const NOTIFICATION: [u8; 30] = [
    0x09, 0x01, 0x1C, 0x02, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x00, 0x00, 0x01, 0x3E, 0x19, 0x05, 0x3F,
    0x49, 0x00, 0x59, 0x64, 0x69, 0x01, 0x89, 0x00, 0x99, 0x00, 0xA9, 0x00, 0xB9, 0x02,
];

fn notification() -> Vec<u8> {
    NOTIFICATION.to_vec()
}

#[test]
fn event_log_record_kinds_have_exact_bytes_and_round_trip() {
    let mut framed_notification = vec![0x1E, 0x1E];
    framed_notification.extend(notification());
    framed_notification.extend([0x1F, 0x1F]);
    for (log_datum, tail) in [
        // log-status [0]: log-disabled, bit 0, in the top bit.
        (
            EventLogDatum::LogStatus(LogStatus::LOG_DISABLED),
            vec![0x1E, 0x0A, 0x05, 0x80, 0x1F],
        ),
        // notification [1] around the request's own fields.
        (
            EventLogDatum::Notification(notification()),
            framed_notification,
        ),
        // time-change [2], unknown amount.
        (
            EventLogDatum::TimeChange(0.0),
            vec![0x1E, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x1F],
        ),
    ] {
        let value = record(log_datum);
        let bytes = encoded(&value);
        assert_eq!(bytes, [&TIMESTAMP[..], &tail].concat(), "{value:?}");
        assert_eq!(
            decode_event_log_record(&bytes, 0).unwrap(),
            (value, bytes.len())
        );
    }
}

#[test]
fn consecutive_event_log_records_decode_by_returned_offset() {
    let first = record(EventLogDatum::Notification(notification()));
    let second = record(EventLogDatum::TimeChange(3.25));
    let mut bytes = encoded(&first);
    bytes.extend(encoded(&second));
    let (decoded, next) = decode_event_log_record(&bytes, 0).unwrap();
    assert_eq!(decoded, first);
    assert_eq!(
        decode_event_log_record(&bytes, next).unwrap(),
        (second, bytes.len())
    );
}

#[test]
fn event_log_record_rejects_unencodable_values_without_writing() {
    for log_datum in [
        // An opening tag left open, and a value cut short.
        EventLogDatum::Notification(vec![0x3E, 0x19, 0x05]),
        EventLogDatum::Notification(vec![0x09]),
    ] {
        let mut buf = BytesMut::from(&b"kept"[..]);
        assert!(encode_event_log_record(&record(log_datum), &mut buf).is_err());
        assert_eq!(&buf[..], b"kept");
    }
}

#[test]
fn event_log_record_decoder_rejects_malformed_records() {
    let good = encoded(&record(EventLogDatum::TimeChange(1.0)));
    let mut cases: Vec<Vec<u8>> = vec![
        good[..good.len() - 1].to_vec(),
        // A Trend Log datum tag, and two alternatives in one datum.
        [&TIMESTAMP[..], &[0x1E, 0x78, 0x1F]].concat(),
        [
            &TIMESTAMP[..],
            &[0x1E, 0x0A, 0x05, 0x80, 0x0A, 0x05, 0x80, 0x1F],
        ]
        .concat(),
        // log-status that isn't a three-bit BitString.
        [&TIMESTAMP[..], &[0x1E, 0x0A, 0x04, 0x60, 0x1F]].concat(),
        // A notification holding a stray application tag cut short.
        [&TIMESTAMP[..], &[0x1E, 0x1E, 0x44, 0x00, 0x1F, 0x1F]].concat(),
    ];
    // A timestamp missing its Time.
    cases.push(vec![
        0x0E, 0xA4, 0x7E, 0x08, 0x1F, 0x01, 0x0F, 0x1E, 0x2C, 0, 0, 0, 0, 0x1F,
    ]);
    for bytes in cases {
        assert!(decode_event_log_record(&bytes, 0).is_err(), "{bytes:02X?}");
    }
}
