use bacnet_objects::event::EventTransition;
use bacnet_services::enrollment_summary::{PriorityFilter, RecipientProcess};
use bacnet_types::bitstring::EventTransitionBits;
use bacnet_types::constructed::BACnetRecipient;
use bacnet_types::enums::{AcknowledgmentFilter, EnrollmentSummaryEventStateFilter, EventType};

use super::enrollment_summary_support::*;
use super::*;

fn database(candidate: SummaryFixture) -> ObjectDatabase {
    let mut db = ObjectDatabase::new();
    db.add(Box::new(candidate)).unwrap();
    db.add(Box::new(class(7, 7, [10, 20, 30], Vec::new())))
        .unwrap();
    db
}

fn candidate(state: EventState, acknowledged: EventTransitionBits) -> SummaryFixture {
    SummaryFixture::candidate(
        1,
        EventType::OUT_OF_RANGE,
        state,
        acknowledged,
        7,
        Some(EventTransition::for_target_state(state)),
    )
}

fn count(
    db: &ObjectDatabase,
    request: &bacnet_services::enrollment_summary::GetEnrollmentSummaryRequest,
) -> usize {
    response(db, request).unwrap().entries.len()
}

#[test]
fn acknowledgment_filter_has_independent_positive_and_negative_cases() {
    let all_acked = database(candidate(EventState::OFFNORMAL, EventTransitionBits::all()));
    let one_unacked = database(candidate(
        EventState::OFFNORMAL,
        EventTransitionBits::TO_FAULT | EventTransitionBits::TO_NORMAL,
    ));

    for (filter, acked_count, unacked_count) in [
        (AcknowledgmentFilter::ALL, 1, 1),
        (AcknowledgmentFilter::ACKED, 1, 0),
        (AcknowledgmentFilter::NOT_ACKED, 0, 1),
    ] {
        let request = bacnet_services::enrollment_summary::GetEnrollmentSummaryRequest {
            acknowledgment_filter: filter,
            ..request()
        };
        assert_eq!(count(&all_acked, &request), acked_count);
        assert_eq!(count(&one_unacked, &request), unacked_count);
    }
}

#[test]
fn enrollment_filter_has_independent_positive_and_negative_cases() {
    let device = ObjectIdentifier::new(ObjectType::DEVICE, 44).unwrap();
    let recipient = BACnetRecipient::Device(device);
    let mut db = database(candidate(EventState::OFFNORMAL, EventTransitionBits::all()));
    db.add(Box::new(class(
        7,
        7,
        [10, 20, 30],
        vec![destination(recipient.clone(), 8)],
    )))
    .unwrap();

    let matching = bacnet_services::enrollment_summary::GetEnrollmentSummaryRequest {
        enrollment_filter: Some(RecipientProcess {
            recipient: recipient.clone(),
            process_identifier: 8,
        }),
        ..request()
    };
    assert_eq!(count(&db, &matching), 1);
    let nonmatching = bacnet_services::enrollment_summary::GetEnrollmentSummaryRequest {
        enrollment_filter: Some(RecipientProcess {
            recipient,
            process_identifier: 9,
        }),
        ..request()
    };
    assert_eq!(count(&db, &nonmatching), 0);
}

#[test]
fn all_event_state_filters_and_omitted_default_have_exact_meanings() {
    let cases = [
        (
            EnrollmentSummaryEventStateFilter::OFFNORMAL,
            EventState::OFFNORMAL,
            EventState::HIGH_LIMIT,
        ),
        (
            EnrollmentSummaryEventStateFilter::FAULT,
            EventState::FAULT,
            EventState::OFFNORMAL,
        ),
        (
            EnrollmentSummaryEventStateFilter::NORMAL,
            EventState::NORMAL,
            EventState::FAULT,
        ),
        (
            EnrollmentSummaryEventStateFilter::ALL,
            EventState::NORMAL,
            EventState::HIGH_LIMIT,
        ),
        (
            EnrollmentSummaryEventStateFilter::ACTIVE,
            EventState::HIGH_LIMIT,
            EventState::NORMAL,
        ),
    ];
    for (filter, positive, negative) in cases {
        let request = bacnet_services::enrollment_summary::GetEnrollmentSummaryRequest {
            event_state_filter: Some(filter),
            ..request()
        };
        assert_eq!(
            count(
                &database(candidate(positive, EventTransitionBits::all())),
                &request
            ),
            1
        );
        let expected_negative = usize::from(filter == EnrollmentSummaryEventStateFilter::ALL);
        assert_eq!(
            count(
                &database(candidate(negative, EventTransitionBits::all())),
                &request
            ),
            expected_negative
        );
    }
    assert_eq!(
        count(
            &database(candidate(EventState::NORMAL, EventTransitionBits::all())),
            &request()
        ),
        1
    );
    assert_eq!(
        count(
            &database(candidate(
                EventState::HIGH_LIMIT,
                EventTransitionBits::all()
            )),
            &request()
        ),
        1
    );
}

#[test]
fn event_type_filter_is_capability_based() {
    let db = database(candidate(EventState::OFFNORMAL, EventTransitionBits::all()));
    let matching = bacnet_services::enrollment_summary::GetEnrollmentSummaryRequest {
        event_type_filter: Some(EventType::OUT_OF_RANGE),
        ..request()
    };
    assert_eq!(count(&db, &matching), 1);
    let nonmatching = bacnet_services::enrollment_summary::GetEnrollmentSummaryRequest {
        event_type_filter: Some(EventType::CHANGE_OF_RELIABILITY),
        ..request()
    };
    assert_eq!(count(&db, &nonmatching), 0);
}

#[test]
fn priority_filter_is_inclusive_and_independent() {
    let db = database(candidate(EventState::OFFNORMAL, EventTransitionBits::all()));
    for range in [(10, 10), (9, 10), (10, 11)] {
        let request = bacnet_services::enrollment_summary::GetEnrollmentSummaryRequest {
            priority_filter: Some(PriorityFilter {
                min_priority: range.0,
                max_priority: range.1,
            }),
            ..request()
        };
        assert_eq!(count(&db, &request), 1);
    }
    let excluded = bacnet_services::enrollment_summary::GetEnrollmentSummaryRequest {
        priority_filter: Some(PriorityFilter {
            min_priority: 11,
            max_priority: 12,
        }),
        ..request()
    };
    assert_eq!(count(&db, &excluded), 0);
}

#[test]
fn notification_class_filter_has_independent_positive_and_negative_cases() {
    let db = database(candidate(EventState::OFFNORMAL, EventTransitionBits::all()));
    for (class_number, expected) in [(7, 1), (8, 0)] {
        let request = bacnet_services::enrollment_summary::GetEnrollmentSummaryRequest {
            notification_class_filter: Some(class_number),
            ..request()
        };
        assert_eq!(count(&db, &request), expected);
    }
}

#[test]
fn all_explicit_filters_are_conjunctive() {
    let recipient = BACnetRecipient::Device(ObjectIdentifier::new(ObjectType::DEVICE, 44).unwrap());
    let mut db = database(candidate(
        EventState::OFFNORMAL,
        EventTransitionBits::TO_FAULT | EventTransitionBits::TO_NORMAL,
    ));
    db.add(Box::new(class(
        7,
        7,
        [10, 20, 30],
        vec![destination(recipient.clone(), 8)],
    )))
    .unwrap();
    let matching = bacnet_services::enrollment_summary::GetEnrollmentSummaryRequest {
        acknowledgment_filter: AcknowledgmentFilter::NOT_ACKED,
        enrollment_filter: Some(RecipientProcess {
            recipient,
            process_identifier: 8,
        }),
        event_state_filter: Some(EnrollmentSummaryEventStateFilter::OFFNORMAL),
        event_type_filter: Some(EventType::OUT_OF_RANGE),
        priority_filter: Some(PriorityFilter {
            min_priority: 10,
            max_priority: 10,
        }),
        notification_class_filter: Some(7),
    };
    assert_eq!(count(&db, &matching), 1);
    let one_filter_fails = bacnet_services::enrollment_summary::GetEnrollmentSummaryRequest {
        event_type_filter: Some(EventType::CHANGE_OF_STATE),
        ..matching
    };
    assert_eq!(count(&db, &one_filter_fails), 0);
}
