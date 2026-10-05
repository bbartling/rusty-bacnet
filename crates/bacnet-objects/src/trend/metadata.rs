use super::TrendLogObject;
use std::borrow::Cow;

use bacnet_types::enums::PropertyIdentifier as P;

use crate::log_buffer::{BUFFER_SIZE_METADATA, LOG_BUFFER_METADATA, TOTAL_RECORD_COUNT_METADATA};
use crate::log_lifecycle::{LOG_ENABLE_METADATA, RECORD_COUNT_METADATA, STOP_WHEN_FULL_METADATA};
use crate::log_window::{START_TIME_METADATA, STOP_TIME_METADATA};
use crate::property_metadata::{
    PropertyConformance::{Optional, RequiredRead},
    PropertyMetadata, PropertyWriteCapability,
    PropertyWriteCapability::{Always, ReadOnly},
};

// The legacy rows keep their order, then the window, alignment and Trigger
// rows follow as on a Trend Log Multiple. Each row keeps its base conformance
// code: Table 12-29 footnotes 1 and 8 require Start_Time, Stop_Time and
// Log_DeviceObjectProperty when the log samples a BACnet property, which
// every log here does, but they stay Optional rather than gaining a presence
// condition. There is no Out_Of_Service row (#985), and Reliability stays
// read-only. Log_DeviceObjectProperty is writable, held to this device
// (#1234). Logging_Type takes POLLED or TRIGGERED, and Log_Interval is
// read-only while TRIGGERED (footnote 3). Start_Time and Stop_Time are
// writable (footnote 2). The device supports clock-aligned logging, so
// Align_Intervals and Interval_Offset are present (footnote 5) and
// writable, as Trigger is, to ask for an acquisition.
const fn rows(log_interval: PropertyWriteCapability) -> [PropertyMetadata; 22] {
    [
        PropertyMetadata::new(P::OBJECT_IDENTIFIER, RequiredRead, None, ReadOnly),
        PropertyMetadata::new(P::OBJECT_NAME, RequiredRead, None, ReadOnly),
        PropertyMetadata::new(P::DESCRIPTION, Optional, None, Always),
        PropertyMetadata::new(P::OBJECT_TYPE, RequiredRead, None, ReadOnly),
        LOG_ENABLE_METADATA,
        PropertyMetadata::new(P::LOG_INTERVAL, Optional, None, log_interval),
        STOP_WHEN_FULL_METADATA,
        BUFFER_SIZE_METADATA,
        LOG_BUFFER_METADATA,
        RECORD_COUNT_METADATA,
        TOTAL_RECORD_COUNT_METADATA,
        PropertyMetadata::new(P::STATUS_FLAGS, RequiredRead, None, ReadOnly),
        PropertyMetadata::new(P::EVENT_STATE, RequiredRead, None, ReadOnly),
        PropertyMetadata::new(P::RELIABILITY, Optional, None, ReadOnly),
        PropertyMetadata::new(P::LOGGING_TYPE, RequiredRead, None, Always),
        PropertyMetadata::new(P::LOG_DEVICE_OBJECT_PROPERTY, Optional, None, Always),
        START_TIME_METADATA,
        STOP_TIME_METADATA,
        PropertyMetadata::new(P::ALIGN_INTERVALS, Optional, None, Always),
        PropertyMetadata::new(P::INTERVAL_OFFSET, Optional, None, Always),
        PropertyMetadata::new(P::TRIGGER, Optional, None, Always),
        PropertyMetadata::new(P::PROPERTY_LIST, RequiredRead, None, ReadOnly),
    ]
}

const WRITABLE_INTERVAL: [PropertyMetadata; 22] = rows(Always);
const READ_ONLY_INTERVAL: [PropertyMetadata; 22] = rows(ReadOnly);

pub(super) fn for_object(object: &TrendLogObject) -> Cow<'_, [PropertyMetadata]> {
    Cow::Borrowed(if object.acquisition.log_interval_writable() {
        &WRITABLE_INTERVAL
    } else {
        &READ_ONLY_INTERVAL
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{ClockFrame, ClockReader};
    use crate::event_log::EventLogObject;
    use crate::property_metadata::PropertyConformance::RequiredWrite;
    use crate::traits::BACnetObject;
    use crate::trend::TrendLogMultipleObject;
    use bacnet_types::enums::{ErrorClass, ErrorCode, LoggingType, ObjectType};
    use bacnet_types::error::Error;
    use bacnet_types::primitives::{Date, PropertyValue, Time};
    use std::sync::Arc;

    /// Both trend objects refuse COV, so neither can be put in it.
    const LOGGING_TYPES: [LoggingType; 2] = [LoggingType::POLLED, LoggingType::TRIGGERED];

    /// Every log's window (#1235, #1353).
    const WINDOW: [P; 2] = [P::START_TIME, P::STOP_TIME];

    /// The rows only the two trend objects serve (#1235, #1354).
    const TREND_ONLY: [P; 3] = [P::ALIGN_INTERVALS, P::INTERVAL_OFFSET, P::TRIGGER];

    struct FixedClock;

    impl ClockReader for FixedClock {
        fn read_clock(&self) -> Option<ClockFrame> {
            Some(ClockFrame {
                local_date: Date {
                    year: 126,
                    month: 9,
                    day: 13,
                    day_of_week: 7,
                },
                local_time: Time {
                    hour: 12,
                    minute: 0,
                    second: 0,
                    hundredths: 0,
                },
                utc_offset: 0,
                daylight_savings_status: false,
            })
        }
    }

    fn objects(capacity: u32, logging_type: LoggingType) -> [Box<dyn BACnetObject>; 3] {
        let mut trend = TrendLogObject::new(1, "TL-1", capacity).unwrap();
        let mut multiple = TrendLogMultipleObject::new(1, "TLM-1", capacity).unwrap();
        let event = EventLogObject::new(1, "EL-1", capacity).unwrap();
        trend.set_logging_type(logging_type).unwrap();
        multiple.set_logging_type(logging_type).unwrap();
        // None of the three has Out_Of_Service (Tables 12-29, 12-35, 12-31).
        [Box::new(trend), Box::new(multiple), Box::new(event)]
    }

    fn assert_error(error: Error, class: ErrorClass, code: ErrorCode) {
        assert!(
            matches!(error, Error::Protocol { class: c, code: e }
            if c == class.to_raw() as u32 && e == code.to_raw() as u32),
            "{error:?}"
        );
    }

    #[test]
    fn property_metadata_log_family_exact_sets_and_indexed_list() {
        // Independent fixtures in the pre-migration property-list order.
        let base = [
            P::OBJECT_IDENTIFIER,
            P::OBJECT_NAME,
            P::DESCRIPTION,
            P::OBJECT_TYPE,
            P::LOG_ENABLE,
            P::LOG_INTERVAL,
            P::STOP_WHEN_FULL,
            P::BUFFER_SIZE,
            P::LOG_BUFFER,
            P::RECORD_COUNT,
            P::TOTAL_RECORD_COUNT,
            P::STATUS_FLAGS,
            P::EVENT_STATE,
            P::RELIABILITY,
        ];
        let base_required = [
            P::OBJECT_IDENTIFIER,
            P::OBJECT_NAME,
            P::OBJECT_TYPE,
            P::LOG_ENABLE,
            P::STOP_WHEN_FULL,
            P::BUFFER_SIZE,
            P::LOG_BUFFER,
            P::RECORD_COUNT,
            P::TOTAL_RECORD_COUNT,
            P::STATUS_FLAGS,
            P::EVENT_STATE,
        ];
        for capacity in [0, 1, 3] {
            for logging_type in LOGGING_TYPES {
                for object in objects(capacity, logging_type) {
                    let kind = object.object_identifier().object_type();
                    let mut all = base.to_vec();
                    let mut required = base_required.to_vec();
                    if kind == ObjectType::EVENT_LOG {
                        // Table 12-31 has no Log_Interval (#1064).
                        all.retain(|&p| p != P::LOG_INTERVAL);
                        all.extend(WINDOW);
                    } else {
                        all.extend([P::LOGGING_TYPE, P::LOG_DEVICE_OBJECT_PROPERTY]);
                        all.extend(WINDOW);
                        all.extend(TREND_ONLY);
                        required.push(P::LOGGING_TYPE);
                    }
                    if kind == ObjectType::TREND_LOG_MULTIPLE {
                        required.insert(4, P::LOG_INTERVAL);
                        required.push(P::LOG_DEVICE_OBJECT_PROPERTY);
                    }
                    required.push(P::PROPERTY_LIST);
                    assert_eq!(object.property_list().as_ref(), all);
                    assert_eq!(object.required_properties().as_ref(), required);
                    assert!(!object.is_createable());
                    assert!(object.is_deleteable());
                    assert!(!object.supports_cov());
                    assert!(!object.is_array_property(P::LOG_BUFFER));
                    let metadata = object.property_metadata();
                    assert!(matches!(metadata, Cow::Borrowed(_)));
                    assert_eq!(metadata.len(), all.len() + 1);
                    for row in metadata.iter() {
                        let p = row.property_identifier;
                        assert_eq!(row.presence_condition, None);
                        let conformance = if matches!(p, P::LOG_ENABLE | P::RECORD_COUNT) {
                            RequiredWrite
                        } else if required.contains(&p) {
                            RequiredRead
                        } else {
                            Optional
                        };
                        assert_eq!(row.conformance, conformance, "{kind:?} {p:?}");
                        assert!(
                            crate::property_metadata_tests::metadata_row_reads(object.as_ref(), p),
                            "{kind:?} {p:?}"
                        );
                    }
                    let wire: Vec<_> = all
                        .iter()
                        .filter(|&&p| {
                            !matches!(p, P::OBJECT_IDENTIFIER | P::OBJECT_NAME | P::OBJECT_TYPE)
                        })
                        .map(|p| PropertyValue::Enumerated(p.to_raw()))
                        .collect();
                    assert_eq!(
                        object.read_property(P::PROPERTY_LIST, None).unwrap(),
                        PropertyValue::List(wire.clone())
                    );
                    assert_eq!(
                        object.read_property(P::PROPERTY_LIST, Some(0)).unwrap(),
                        PropertyValue::Unsigned(wire.len() as u64)
                    );
                    for (i, value) in wire.iter().enumerate() {
                        assert_eq!(
                            object
                                .read_property(P::PROPERTY_LIST, Some(i as u32 + 1))
                                .unwrap(),
                            *value
                        );
                    }
                    assert_error(
                        object
                            .read_property(P::PROPERTY_LIST, Some(wire.len() as u32 + 1))
                            .unwrap_err(),
                        ErrorClass::PROPERTY,
                        ErrorCode::INVALID_ARRAY_INDEX,
                    );
                    assert_eq!(object.log_buffer_internal().unwrap().record_count(), 0);
                }
            }
        }
    }

    #[test]
    fn property_metadata_log_family_write_capabilities_match_dispatch() {
        for logging_type in LOGGING_TYPES {
            for mut object in objects(8, logging_type) {
                object.bind_clock_internal(Some(Arc::new(FixedClock)));
                let kind = object.object_identifier().object_type();
                let metadata = object.property_metadata().into_owned();
                for row in &metadata {
                    let p = row.property_identifier;
                    let capability = match p {
                        P::LOG_ENABLE
                        | P::STOP_WHEN_FULL
                        | P::RECORD_COUNT
                        | P::DESCRIPTION
                        | P::LOG_DEVICE_OBJECT_PROPERTY => Always,
                        // Read-only while a trend log is TRIGGERED (Table
                        // 12-29 footnote 3, Table 12-35 footnote 2).
                        P::LOG_INTERVAL if logging_type == LoggingType::TRIGGERED => ReadOnly,
                        P::LOG_INTERVAL | P::LOGGING_TYPE => Always,
                        p if WINDOW.contains(&p) || TREND_ONLY.contains(&p) => Always,
                        _ => ReadOnly,
                    };
                    assert_eq!(row.write_capability, capability, "{kind:?} {p:?}");
                    assert_eq!(object.is_writable_property(p), capability.is_writable());
                    if p == P::LOG_BUFFER {
                        // Present but readable only by ReadRange (#1237);
                        // writes are denied.
                        for value in [PropertyValue::List(vec![]), PropertyValue::Null] {
                            assert_error(
                                object.write_property(p, None, value, None).unwrap_err(),
                                ErrorClass::PROPERTY,
                                ErrorCode::WRITE_ACCESS_DENIED,
                            );
                        }
                        continue;
                    }
                    let value = match p {
                        P::LOG_ENABLE => PropertyValue::Boolean(false),
                        P::LOG_INTERVAL => PropertyValue::Unsigned(17),
                        P::STOP_WHEN_FULL => PropertyValue::Boolean(true),
                        P::RECORD_COUNT => PropertyValue::Unsigned(0),
                        _ => object.read_property(p, None).unwrap(),
                    };
                    let result = object.write_property(p, None, value, None);
                    if capability == Always {
                        result.unwrap();
                    } else {
                        assert_error(
                            result.unwrap_err(),
                            ErrorClass::PROPERTY,
                            ErrorCode::WRITE_ACCESS_DENIED,
                        );
                    }
                    let before = object.read_property(p, None).unwrap();
                    if capability == Always && p == P::DESCRIPTION {
                        object
                            .write_property(p, None, PropertyValue::Null, None)
                            .unwrap();
                        assert_eq!(object.read_property(p, None).unwrap(), before);
                        assert_error(
                            object
                                .write_property(p, None, PropertyValue::Unsigned(1), None)
                                .unwrap_err(),
                            ErrorClass::PROPERTY,
                            ErrorCode::INVALID_DATA_TYPE,
                        );
                        continue;
                    }
                    // Null is no reference on either trend object; their
                    // unset form is a reference to instance 4194303 (#1417).
                    assert_error(
                        object
                            .write_property(p, None, PropertyValue::Null, None)
                            .unwrap_err(),
                        ErrorClass::PROPERTY,
                        if capability == Always {
                            ErrorCode::INVALID_DATA_TYPE
                        } else {
                            ErrorCode::WRITE_ACCESS_DENIED
                        },
                    );
                }
                assert_error(
                    object
                        .write_property(P::RECORD_COUNT, None, PropertyValue::Unsigned(1), None)
                        .unwrap_err(),
                    ErrorClass::PROPERTY,
                    ErrorCode::INVALID_DATA_TYPE,
                );
                // No log object has Out_Of_Service (#985, #1064), and only the
                // trend objects serve Logging_Type, alignment and Trigger.
                let absent = [
                    P::PRESENT_VALUE,
                    P::PRIORITY_ARRAY,
                    P::ALL,
                    P::OUT_OF_SERVICE,
                ]
                .into_iter()
                .chain(
                    [P::LOGGING_TYPE]
                        .into_iter()
                        .chain(TREND_ONLY)
                        .filter(|_| kind == ObjectType::EVENT_LOG),
                );
                for p in absent {
                    assert!(!object.is_writable_property(p));
                    assert_error(
                        object.read_property(p, None).unwrap_err(),
                        ErrorClass::PROPERTY,
                        ErrorCode::UNKNOWN_PROPERTY,
                    );
                    assert_error(
                        object
                            .write_property(p, None, PropertyValue::Null, None)
                            .unwrap_err(),
                        ErrorClass::PROPERTY,
                        ErrorCode::UNKNOWN_PROPERTY,
                    );
                }
                assert_eq!(object.property_metadata().as_ref(), metadata);
            }
        }
    }

    #[test]
    fn property_metadata_log_capability_does_not_bypass_clock_validation() {
        for mut object in objects(3, LoggingType::POLLED) {
            let metadata = object.property_metadata().into_owned();
            for (p, value) in [
                (P::LOG_ENABLE, PropertyValue::Boolean(false)),
                (P::RECORD_COUNT, PropertyValue::Unsigned(0)),
            ] {
                assert!(object.is_writable_property(p));
                assert_error(
                    object.write_property(p, None, value, None).unwrap_err(),
                    ErrorClass::DEVICE,
                    ErrorCode::OPERATIONAL_PROBLEM,
                );
                assert_eq!(
                    object.read_property(P::LOG_ENABLE, None).unwrap(),
                    PropertyValue::Boolean(true)
                );
                assert_eq!(object.log_buffer_internal().unwrap().record_count(), 0);
                assert_eq!(object.property_metadata().as_ref(), metadata);
            }
        }
    }
}
