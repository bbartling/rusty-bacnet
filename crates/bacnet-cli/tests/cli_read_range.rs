//! `bacnet read-range` decodes the records of a log buffer by the log object's
//! type (#1274), against a loopback server.
#[allow(dead_code)]
mod support;

use std::net::Ipv4Addr;

use bacnet_objects::database::ObjectDatabase;
use bacnet_objects::device::{DeviceConfig, DeviceObject};
use bacnet_objects::event_log::EventLogObject;
use bacnet_objects::traits::BACnetObject;
use bacnet_objects::trend::{TrendLogMultipleObject, TrendLogObject};
use bacnet_server::server::BACnetServer;
use bacnet_transport::bip::BipTransport;
use bacnet_types::bitstring::LogStatus;
use bacnet_types::constructed::{
    BACnetEventLogRecord, BACnetLogMultipleRecord, BACnetLogRecord, EventLogDatum,
    EventNotificationRequest, LogData, LogDatum, LogValue,
};
use bacnet_types::enums::{EventState, EventType, NotifyType, ObjectType};
use bacnet_types::primitives::{BACnetTimeStamp, Date, ObjectIdentifier, StatusFlags, Time};
use serde_json::json;
use support::run;

const DATE: Date = Date {
    year: 126,
    month: 10,
    day: 3,
    day_of_week: 6,
};

fn time(hour: u8) -> Time {
    Time {
        hour,
        minute: 0,
        second: 0,
        hundredths: 0,
    }
}

fn oid(object_type: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(object_type, instance).unwrap()
}

fn alarm() -> EventNotificationRequest {
    EventNotificationRequest {
        process_identifier: 1,
        initiating_device_identifier: oid(ObjectType::DEVICE, 1),
        event_object_identifier: oid(ObjectType::ANALOG_INPUT, 3),
        timestamp: BACnetTimeStamp::SequenceNumber(5),
        notification_class: 0,
        priority: 100,
        event_type: EventType::OUT_OF_RANGE,
        message_text: Some("too hot".into()),
        notify_type: NotifyType::ALARM,
        ack_required: true,
        from_state: EventState::NORMAL,
        to_state: EventState::HIGH_LIMIT,
        event_values: None,
    }
}

/// A server on loopback holding Trend Log 1, Event Log 1 and Trend Log
/// Multiple 1, each with records.
async fn server() -> BACnetServer<BipTransport> {
    let mut device = DeviceObject::new(DeviceConfig {
        instance: 1,
        name: "read-range".into(),
        ..DeviceConfig::default()
    })
    .unwrap();

    let mut trend = TrendLogObject::new(1, "TL-1", 10).unwrap();
    trend
        .add_record(BACnetLogRecord {
            date: DATE,
            time: time(8),
            log_datum: LogDatum::RealValue(72.5),
            status_flags: Some(StatusFlags::IN_ALARM),
        })
        .unwrap();
    trend
        .add_record(BACnetLogRecord {
            date: DATE,
            time: time(9),
            log_datum: LogDatum::LogStatus(LogStatus::BUFFER_PURGED),
            status_flags: None,
        })
        .unwrap();

    let mut events = EventLogObject::new(1, "EL-1", 10).unwrap();
    for (hour, log_datum) in [
        (8, EventLogDatum::Notification(alarm())),
        (9, EventLogDatum::TimeChange(-1.5)),
    ] {
        events
            .add_record(BACnetEventLogRecord {
                date: DATE,
                time: time(hour),
                log_datum,
            })
            .unwrap();
    }

    let mut multiple = TrendLogMultipleObject::new(1, "TLM-1", 10).unwrap();
    multiple
        .add_record(BACnetLogMultipleRecord {
            date: DATE,
            time: time(8),
            log_data: LogData::Values(vec![LogValue::RealValue(21.5), LogValue::NullValue]),
        })
        .unwrap();

    let objects: Vec<Box<dyn BACnetObject>> =
        vec![Box::new(trend), Box::new(events), Box::new(multiple)];
    let mut list = vec![device.object_identifier()];
    list.extend(objects.iter().map(|object| object.object_identifier()));
    device.set_object_list(list);

    let mut db = ObjectDatabase::new();
    db.add(Box::new(device)).unwrap();
    for object in objects {
        db.add(object).unwrap();
    }
    BACnetServer::bip_builder()
        .interface(Ipv4Addr::LOCALHOST)
        .port(0)
        .database(db)
        .build()
        .await
        .unwrap()
}

/// The server's `ip:port`, as the CLI takes a target.
fn target(server: &BACnetServer<BipTransport>) -> String {
    let mac = server.local_mac();
    let port = u16::from_be_bytes([mac[4], mac[5]]);
    format!("{}:{port}", Ipv4Addr::new(mac[0], mac[1], mac[2], mac[3]))
}

/// Run `read-range` against `target` for `object` with output `format`,
/// returning its stdout.
async fn read_range(target: &str, object: &str, format: &str) -> String {
    let output = run([
        "--interface",
        "127.0.0.1",
        "--port",
        "0",
        "--format",
        format,
        "read-range",
        target,
        object,
    ])
    .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[tokio::test]
async fn read_range_prints_decoded_log_records() {
    let mut server = server().await;
    let target = target(&server);

    let trend: serde_json::Value =
        serde_json::from_str(&read_range(&target, "trend-log:1", "json").await).unwrap();
    assert_eq!(
        trend,
        json!({
            "object": "TREND_LOG:1",
            "property": "LOG_BUFFER",
            "item_count": 2,
            "records": [
                {
                    "timestamp": "2026-10-03 08:00:00.00",
                    "datum": "72.5",
                    "status_flags": "IN_ALARM",
                },
                {
                    "timestamp": "2026-10-03 09:00:00.00",
                    "datum": "log-status BUFFER_PURGED",
                },
            ],
        })
    );

    let events: serde_json::Value =
        serde_json::from_str(&read_range(&target, "event-log:1", "json").await).unwrap();
    assert_eq!(
        events,
        json!({
            "object": "EVENT_LOG:1",
            "property": "LOG_BUFFER",
            "item_count": 2,
            "records": [
                {
                    "timestamp": "2026-10-03 08:00:00.00",
                    "datum": "ALARM OUT_OF_RANGE ANALOG_INPUT:3 NORMAL -> HIGH_LIMIT \"too hot\"",
                },
                {
                    "timestamp": "2026-10-03 09:00:00.00",
                    "datum": "time-change -1.5 s",
                },
            ],
        })
    );

    let multiple: serde_json::Value =
        serde_json::from_str(&read_range(&target, "trend-log-multiple:1", "json").await).unwrap();
    assert_eq!(
        multiple["records"],
        json!([{ "timestamp": "2026-10-03 08:00:00.00", "datum": "[21.5, null]" }])
    );

    // The table shows the same records, one row each, with nothing left as
    // hex; only the Trend Log's has a status flags column.
    let table = read_range(&target, "event-log:1", "table").await;
    assert!(table.starts_with("ReadRange EVENT_LOG:1  LOG_BUFFER  count=2\n"));
    for cell in [
        "2026-10-03 08:00:00.00",
        "ALARM OUT_OF_RANGE ANALOG_INPUT:3 NORMAL -> HIGH_LIMIT \"too hot\"",
        "time-change -1.5 s",
    ] {
        assert!(table.contains(cell), "{cell}: {table}");
    }
    assert!(!table.contains("Status flags"), "{table}");
    assert!(!table.contains("[raw]"), "{table}");
    let table = read_range(&target, "trend-log:1", "table").await;
    assert!(table.contains("Status flags"), "{table}");
    assert!(table.contains("IN_ALARM"), "{table}");

    server.stop().await.unwrap();
}
