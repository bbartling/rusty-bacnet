//! ReadRange over the Device's live COV subscription lists (#1046; Clauses
//! 12.11 and 15.8). ReadRange pages the request-local projection ReadProperty
//! serves, so a page's items, joined in order, are a run of the ReadProperty
//! value's elements, and a request reads one snapshot of the COV table.
use super::*;
use bacnet_encoding::constructed::{encode_cov_multiple_subscription, encode_cov_subscription};
use bacnet_services::read_range::{RangeSpec, ReadRangeAck, ReadRangeRequest};
use std::ops::Range;

type Refusal = (ErrorClass, ErrorCode);

/// A request's range, the run of elements it should return and its flags.
type PageCase = (Option<RangeSpec>, Range<usize>, (bool, bool, bool));

fn position(reference_index: u64, count: i32) -> Option<RangeSpec> {
    Some(RangeSpec::ByPosition {
        reference_index,
        count,
    })
}

fn read_range_request(
    property: PropertyIdentifier,
    range: Option<RangeSpec>,
) -> (ConfirmedServiceChoice, BytesMut) {
    let mut request = BytesMut::new();
    ReadRangeRequest {
        object_identifier: device(),
        property_identifier: property,
        property_array_index: None,
        range,
    }
    .encode(&mut request)
    .unwrap();
    (ConfirmedServiceChoice::READ_RANGE, request)
}

fn read_range_ack(response: Apdu, property: PropertyIdentifier) -> Result<ReadRangeAck, Refusal> {
    match response {
        Apdu::ComplexAck(ack) => {
            let ack = ReadRangeAck::decode(&ack.service_ack).unwrap();
            assert_eq!(
                (ack.object_identifier, ack.property_identifier),
                (device(), property)
            );
            Ok(ack)
        }
        Apdu::Error(error) => Err((error.error_class, error.error_code)),
        other => panic!("unexpected ReadRange response {other:?}"),
    }
}

async fn read_range(
    wire: &mut Wire,
    property: PropertyIdentifier,
    range: Option<RangeSpec>,
) -> Result<ReadRangeAck, Refusal> {
    let response = wire
        .send(&direct(), read_range_request(property, range))
        .await;
    read_range_ack(response, property)
}

/// The ReadProperty value cut into elements with the suite's independent
/// decoders, each re-encoded alone; together they rebuild the value.
fn elements(property: PropertyIdentifier, value: &[u8]) -> Vec<Vec<u8>> {
    let elements: Vec<Vec<u8>> = if property == ACTIVE {
        decode_subscriptions(value)
            .iter()
            .map(|subscription| {
                let mut encoded = BytesMut::new();
                encode_cov_subscription(&mut encoded, subscription).unwrap();
                encoded.to_vec()
            })
            .collect()
    } else {
        decode_contexts(value)
            .iter()
            .map(|context| {
                let mut encoded = BytesMut::new();
                encode_cov_multiple_subscription(&mut encoded, context).unwrap();
                encoded.to_vec()
            })
            .collect()
    };
    assert_eq!(elements.concat(), value, "{property:?} elements");
    elements
}

/// A ReadRange between two ReadProperty reads of the same list, with the
/// ReadProperty value's elements. Time remaining counts down in whole
/// seconds, so a pair that straddles a second boundary is retried; once the
/// two reads agree, the list did not change in between.
async fn bracketed(
    wire: &mut Wire,
    property: PropertyIdentifier,
    range: Option<RangeSpec>,
) -> (Vec<Vec<u8>>, ReadRangeAck) {
    for _ in 0..5 {
        let before = wire.read(device(), property, None).await.unwrap();
        let ack = read_range(wire, property, range.clone()).await;
        let after = wire.read(device(), property, None).await.unwrap();
        if before == after {
            let ack = ack.unwrap_or_else(|refusal| panic!("{property:?} {range:?}: {refusal:?}"));
            return (elements(property, &before), ack);
        }
    }
    panic!("{property:?} changed across five bracketed reads");
}

fn assert_page(
    ack: &ReadRangeAck,
    elements: &[Vec<u8>],
    range: Range<usize>,
    flags: (bool, bool, bool),
) {
    assert_eq!(ack.item_count as usize, range.len(), "{range:?}");
    assert_eq!(ack.item_data, elements[range.clone()].concat(), "{range:?}");
    assert_eq!(ack.result_flags, flags, "{range:?}");
    assert_eq!(ack.first_sequence_number, None);
}

/// Every whole-list and By Position page of `property` equals the matching
/// run of ReadProperty's elements, with the endpoint flags of that run.
async fn assert_pages_follow_read_property(
    wire: &mut Wire,
    property: PropertyIdentifier,
    count: usize,
    cases: &[PageCase],
) {
    for (range, expected, flags) in cases {
        let (elements, ack) = bracketed(wire, property, range.clone()).await;
        assert_eq!(elements.len(), count, "{property:?}");
        assert_page(&ack, &elements, expected.clone(), *flags);
    }
    // Neither list numbers or timestamps its items.
    let sequence = Some(RangeSpec::BySequenceNumber {
        reference_seq: 1,
        count: 1,
    });
    assert_eq!(
        read_range(wire, property, sequence).await.unwrap_err(),
        (ErrorClass::PROPERTY, ErrorCode::LIST_ITEM_NOT_NUMBERED)
    );
}

#[tokio::test]
async fn active_cov_read_range_pages_live_subscriptions_as_read_property_lists_them() {
    let mut wire = Wire::start(ServerConfig::default()).await;
    // Unconfirmed and confirmed, ordinary and single-property, finite and
    // indefinite, direct and routed.
    simple_ack(
        wire.send(&direct(), subscribe_cov(11, av(1), Some(false), Some(300)))
            .await,
    );
    let single = (12, PV, None, Some(1.5), Some(true), Some(600));
    simple_ack(
        wire.send(&routed(), subscribe_cov_property(av(1), single))
            .await,
    );
    let element = (
        13,
        PropertyIdentifier::PRIORITY_ARRAY,
        Some(8),
        None,
        Some(false),
        Some(900),
    );
    simple_ack(
        wire.send(&direct(), subscribe_cov_property(av(1), element))
            .await,
    );
    simple_ack(
        wire.send(&direct(), subscribe_cov(14, av(2), Some(true), None))
            .await,
    );
    let listed = wire.active().await;
    assert_eq!(processes(&listed), vec![11, 12, 13, 14]);
    assert!(find(&listed, 12).issue_confirmed_notifications);
    assert!(!find(&listed, 13).issue_confirmed_notifications);

    // On dev every case answered SERVICES / OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED.
    assert_pages_follow_read_property(
        &mut wire,
        ACTIVE,
        4,
        &[
            (None, 0..4, (true, true, false)),
            (position(1, 2), 0..2, (true, false, false)),
            (position(2, 2), 1..3, (false, false, false)),
            (position(3, 5), 2..4, (false, true, false)),
            (position(4, -2), 2..4, (false, true, false)),
            (position(2, -5), 0..2, (true, false, false)),
            (position(5, 1), 0..0, (false, false, false)),
        ],
    )
    .await;
    wire.server.stop().await.unwrap();
}

#[tokio::test]
async fn active_cov_multiple_read_range_pages_live_contexts_as_read_property_lists_them() {
    let mut wire = Wire::start(ServerConfig::default()).await;
    let flags = PropertyIdentifier::STATUS_FLAGS;
    let array = PropertyIdentifier::PRIORITY_ARRAY;
    // One recipient and process in both forms, and a routed recipient whose
    // context nests two monitored objects.
    let requests = [
        (
            direct(),
            subscribe_cov_property_multiple(
                71,
                false,
                Some((300, 5)),
                vec![(av(1), vec![(PV, None, Some(0.5), true), plain(flags)])],
            ),
        ),
        (
            direct(),
            subscribe_cov_property_multiple(
                71,
                true,
                Some((400, 2)),
                vec![(av(2), vec![plain(PV)])],
            ),
        ),
        (
            routed(),
            subscribe_cov_property_multiple(
                72,
                false,
                Some((500, 1)),
                vec![
                    (av(1), vec![(array, Some(8), None, false)]),
                    (av(2), vec![plain(PV)]),
                ],
            ),
        ),
    ];
    for (peer, request) in requests {
        simple_ack(wire.send(&peer, request).await);
    }
    let contexts = wire.multiple().await;
    assert_eq!(contexts.len(), 3, "{contexts:?}");

    assert_pages_follow_read_property(
        &mut wire,
        MULTIPLE,
        3,
        &[
            (None, 0..3, (true, true, false)),
            (position(1, 1), 0..1, (true, false, false)),
            (position(2, 1), 1..2, (false, false, false)),
            (position(3, -2), 1..3, (false, true, false)),
            (position(4, 1), 0..0, (false, false, false)),
        ],
    )
    .await;
    wire.server.stop().await.unwrap();
}

#[tokio::test]
async fn active_cov_read_range_byte_cap_keeps_whole_elements_in_read_property_order() {
    const CAP: usize = 160;
    let mut wire = Wire::start(ServerConfig {
        read_range_budget: ReadRangeBudget {
            max_service_ack_bytes: CAP,
            ..ReadRangeBudget::default()
        },
        ..ServerConfig::default()
    })
    .await;
    for process in 1..=6 {
        simple_ack(
            wire.send(&direct(), subscribe_cov(process, av(1), Some(false), None))
                .await,
        );
    }
    for process in 71..=74 {
        let request = subscribe_cov_property_multiple(
            process,
            false,
            Some((600, 1)),
            vec![(av(1), vec![plain(PV)])],
        );
        simple_ack(wire.send(&direct(), request).await);
    }
    for property in [ACTIVE, MULTIPLE] {
        // Forward from the first element and backward from the last: each
        // page stops at the last whole element under the cap, flags MORE_ITEMS
        // and keeps ReadProperty's order.
        let (elements, forward) = bracketed(&mut wire, property, None).await;
        let total = elements.len();
        let kept = forward.item_count as usize;
        assert!(0 < kept && kept < total, "{property:?}: {kept} of {total}");
        assert_page(&forward, &elements, 0..kept, (true, false, true));
        let fits = |ack: &ReadRangeAck| {
            let mut encoded = BytesMut::new();
            ack.encode(&mut encoded);
            encoded.len() <= CAP
        };
        assert!(fits(&forward));
        let one_more = ReadRangeAck {
            item_count: kept as u32 + 1,
            item_data: elements[..=kept].concat(),
            ..forward.clone()
        };
        assert!(!fits(&one_more), "{property:?}: the next element fits");

        let last = position(total as u64, -(total as i32));
        let (elements, backward) = bracketed(&mut wire, property, last).await;
        let kept = backward.item_count as usize;
        assert!(0 < kept && kept < total, "{property:?}: {kept} of {total}");
        assert_page(
            &backward,
            &elements,
            total - kept..total,
            (false, true, true),
        );
    }
    wire.server.stop().await.unwrap();
}

#[tokio::test]
async fn active_cov_read_range_reads_empty_lists_as_no_items() {
    let mut wire = Wire::start(ServerConfig::default()).await;
    let pages = [None, position(1, 3), position(1, -3)];
    for property in [ACTIVE, MULTIPLE] {
        assert_eq!(wire.read(device(), property, None).await, Ok(Vec::new()));
        for range in pages.clone() {
            // On dev: SERVICES / OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED.
            let ack = read_range(&mut wire, property, range).await.unwrap();
            assert_page(&ack, &[], 0..0, (false, false, false));
        }
    }
    // Lists emptied by cancellation read the same way.
    for request in [
        subscribe_cov(5, av(1), Some(false), Some(60)),
        subscribe_cov(5, av(1), None, None),
        subscribe_cov_property_multiple(6, false, Some((60, 1)), vec![(av(1), vec![plain(PV)])]),
        subscribe_cov_property_multiple(6, false, None, vec![]),
    ] {
        simple_ack(wire.send(&direct(), request).await);
    }
    for property in [ACTIVE, MULTIPLE] {
        let ack = read_range(&mut wire, property, None).await.unwrap();
        assert_page(&ack, &[], 0..0, (false, false, false));
    }
    wire.server.stop().await.unwrap();
}

/// The subscriber processes a page lists, in list order.
fn page_processes(property: PropertyIdentifier, ack: &ReadRangeAck) -> Vec<u32> {
    let processes: Vec<u32> = if property == ACTIVE {
        decode_subscriptions(&ack.item_data)
            .iter()
            .map(|subscription| subscription.recipient.process_identifier)
            .collect()
    } else {
        decode_contexts(&ack.item_data)
            .iter()
            .map(|context| context.recipient.process_identifier)
            .collect()
    };
    assert_eq!(processes.len(), ack.item_count as usize, "{property:?}");
    processes
}

/// One routed process's entry in both lists: an ordinary subscription and a
/// COV-multiple context, each on AV-1.
fn subscribe_both(process: u32) -> [(ConfirmedServiceChoice, BytesMut); 2] {
    [
        subscribe_cov(process, av(1), Some(false), None),
        subscribe_cov_property_multiple(
            process,
            false,
            Some((600, 1)),
            vec![(av(1), vec![plain(PV)])],
        ),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_cov_read_range_pages_stay_whole_while_subscriptions_change() {
    const PROCESSES: u32 = 8;
    let mut wire = Wire::start(ServerConfig::default()).await;
    // Processes 1 and 2 stay subscribed throughout. The writer then grows
    // both lists to 1..=8 and shrinks them back from the top, over and over,
    // so every instant lists 1..=k of each, with k at least 2.
    for request in [1, 2].into_iter().flat_map(subscribe_both) {
        simple_ack(wire.send(&routed(), request).await);
    }
    let tx = wire.tx.clone();
    let writer = tokio::spawn(async move {
        let peer = routed();
        // Clear of the invoke IDs the baseline requests used.
        let mut invoke_id = 100u8;
        let mut send = |request| {
            invoke_id += 1;
            exchange(&tx, &peer, invoke_id, request)
        };
        for _ in 0..3 {
            for process in 3..=PROCESSES {
                for request in subscribe_both(process) {
                    simple_ack(send(request).await);
                }
            }
            for process in (3..=PROCESSES).rev() {
                let cancel = subscribe_cov_property_multiple(process, false, None, vec![]);
                simple_ack(send(cancel).await);
                simple_ack(send(subscribe_cov(process, av(1), None, None)).await);
            }
        }
    });
    // Each page is one snapshot: its items are whole elements, a contiguous
    // run of 1..=k, and its flags describe that same run.
    let mut reads = 0;
    while !writer.is_finished() && reads < 50 {
        reads += 1;
        for property in [ACTIVE, MULTIPLE] {
            let whole = read_range(&mut wire, property, None).await.unwrap();
            let listed = page_processes(property, &whole);
            let k = listed.len() as u32;
            assert!(k >= 2, "{property:?}: the live list, not a placeholder");
            assert_eq!(listed, (1..=k).collect::<Vec<_>>(), "{property:?}");
            assert_eq!(whole.result_flags, (true, true, false), "{property:?}");

            let page = read_range(&mut wire, property, position(2, 3))
                .await
                .unwrap();
            let listed = page_processes(property, &page);
            let n = listed.len() as u32;
            assert!((1..=3).contains(&n), "{property:?}: {listed:?}");
            assert_eq!(listed, (2..2 + n).collect::<Vec<_>>(), "{property:?}");
            let (first, last, more) = page.result_flags;
            assert!(!first && !more, "{property:?}: {:?}", page.result_flags);
            // A short page ends the list; a full one may or may not.
            assert!(n == 3 || last, "{property:?}: {listed:?} without LAST_ITEM");
        }
    }
    writer.await.unwrap();
    for property in [ACTIVE, MULTIPLE] {
        let (elements, ack) = bracketed(&mut wire, property, None).await;
        assert_eq!(elements.len(), 2, "{property:?}");
        assert_page(&ack, &elements, 0..2, (true, true, false));
    }
    wire.server.stop().await.unwrap();
}
