//! Restoring or seeding a log's buffer and Total_Record_Count (#1537).
use super::*;

const MAX: u64 = u32::MAX as u64;

fn samples(hours: std::ops::Range<u8>) -> Vec<BACnetLogRecord> {
    hours.map(|hour| ordinary(hour, u64::from(hour))).collect()
}

/// What a refused restore must leave as it was.
fn state(object: &Family) -> (VecDeque<BACnetLogRecord>, Vec<u64>, u64) {
    (object.records(), object.identities(), object.total())
}

#[test]
fn restored_records_number_back_from_the_count_across_the_wrap() {
    for kind in FamilyKind::ALL {
        let mut log = kind.object(5);
        log.restore(10, samples(1..4)).unwrap();
        assert_eq!(log.identities(), vec![8, 9, 10], "{kind:?}");
        assert_eq!(log.records(), VecDeque::from(samples(1..4)), "{kind:?}");

        // A count below the number of records has wrapped (Clause 12.25.16).
        log.restore(2, samples(1..5)).unwrap();
        assert_eq!(log.identities(), vec![MAX - 1, MAX, 1, 2], "{kind:?}");
        assert_eq!(log.total(), 2, "{kind:?}");
        assert_eq!(
            log.read(PropertyIdentifier::RECORD_COUNT),
            PropertyValue::Unsigned(4),
            "{kind:?}"
        );
        log.add_record(ordinary(9, 9)).unwrap();
        assert_eq!(log.identities(), vec![MAX - 1, MAX, 1, 2, 3], "{kind:?}");
        assert_eq!(log.total(), 3, "{kind:?}");
    }
}

#[test]
fn a_seed_near_the_wrap_numbers_new_records_across_it() {
    for kind in FamilyKind::ALL {
        let mut log = kind.object(5);
        log.add_record(ordinary(1, 1)).unwrap();
        log.restore(u32::MAX - 1, Vec::new()).unwrap();
        assert!(log.records().is_empty(), "{kind:?}");
        assert_eq!(log.total(), MAX - 1, "{kind:?}");
        for hour in 2..5 {
            log.add_record(ordinary(hour, u64::from(hour))).unwrap();
        }
        assert_eq!(log.identities(), vec![MAX, 1, 2], "{kind:?}");
        assert_eq!(log.total(), 2, "{kind:?}");
    }
}

#[test]
fn inconsistent_restores_are_refused_and_change_nothing() {
    for kind in FamilyKind::ALL {
        let mut log = kind.object(3);
        log.bind_clock(TestClock::valid());
        log.add_record(ordinary(1, 1)).unwrap();
        log.write(
            PropertyIdentifier::STOP_WHEN_FULL,
            PropertyValue::Boolean(true),
        )
        .unwrap();
        let before = state(&log);
        for (total, records) in [
            // More records than Buffer_Size.
            (10, samples(1..5)),
            // Records that no count has numbered.
            (0, samples(1..2)),
            // A full buffer under Stop_When_Full while Enable is TRUE.
            (3, samples(1..4)),
        ] {
            let error = log.restore(total, records).unwrap_err();
            assert!(matches!(error, Error::OutOfRange(_)), "{kind:?} {error:?}");
            assert_eq!(state(&log), before, "{kind:?} {total}");
        }

        // One short of full is a state the log reaches itself.
        log.restore(2, samples(1..3)).unwrap();
        assert_eq!(log.identities(), vec![1, 2], "{kind:?}");
        // With Enable FALSE, a stopped log may be full.
        log.write(
            PropertyIdentifier::LOG_ENABLE,
            PropertyValue::Boolean(false),
        )
        .unwrap();
        log.restore(3, samples(1..4)).unwrap();
        assert_eq!(log.identities(), vec![1, 2, 3], "{kind:?}");
    }
}

#[test]
fn a_zero_capacity_log_restores_only_its_count() {
    for kind in FamilyKind::ALL {
        let mut log = kind.object(0);
        log.restore(5, Vec::new()).unwrap();
        assert_eq!(log.total(), 5, "{kind:?}");
        assert!(matches!(
            log.restore(6, samples(1..2)).unwrap_err(),
            Error::OutOfRange(_)
        ));
        assert_eq!(log.total(), 5, "{kind:?}");
        log.restore(0, Vec::new()).unwrap();
        assert_eq!(log.total(), 0, "{kind:?}");
    }
}

#[test]
fn a_record_that_would_not_encode_is_refused() {
    let mut log = TrendLogObject::new(1, "TL-1", 5).unwrap();
    log.add_record(ordinary(1, 1)).unwrap();
    let records = log.records().clone();
    // An any-value that opens a context tag and never closes it.
    let open = BACnetLogRecord {
        log_datum: LogDatum::AnyValue(vec![0x3E, 0x19, 0x05]),
        ..ordinary(2, 2)
    };
    log.restore_log_buffer(7, [ordinary(3, 3), open])
        .unwrap_err();
    assert_eq!(log.records(), &records);
    assert_eq!(log.total_record_count(), 1);
}

#[test]
fn buffer_ready_counts_from_the_restored_count() {
    for kind in FamilyKind::ALL {
        let mut log = kind.object(10);
        log.write(
            PropertyIdentifier::NOTIFICATION_THRESHOLD,
            PropertyValue::Unsigned(2),
        )
        .unwrap();
        log.restore(1_000, samples(1..4)).unwrap();
        // The jump from 0 to 1,000 is no collection: nothing is due.
        assert!(
            log.object_mut().evaluate_intrinsic_reporting().is_none(),
            "{kind:?}"
        );
        assert_eq!(
            log.read(PropertyIdentifier::LAST_NOTIFY_RECORD),
            PropertyValue::Unsigned(1_000),
            "{kind:?}"
        );
        assert_eq!(
            log.read(PropertyIdentifier::RECORDS_SINCE_NOTIFICATION),
            PropertyValue::Unsigned(0),
            "{kind:?}"
        );
        log.add_record(ordinary(5, 5)).unwrap();
        assert!(log.object_mut().evaluate_intrinsic_reporting().is_none());
        log.add_record(ordinary(6, 6)).unwrap();
        assert!(
            log.object_mut().evaluate_intrinsic_reporting().is_some(),
            "{kind:?}"
        );
    }
}
