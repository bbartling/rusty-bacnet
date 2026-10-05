//! An event notification to a Device recipient the server has no binding for
//! looks for the device with a targeted Who-Is and waits for its I-Am (#1368),
//! while the notification's other recipients are served at once.
//!
//! The harness is a running server whose AV-1 reports a high-limit alarm to
//! Notification Class 0. Writing 85 raises it, writing 50 clears it. The
//! class names Device 9, which the server holds no binding for, and a peer on
//! this network by address. The clock is paused, and the server's APDU
//! timeout, the probe's wait, is the default 3 seconds.
use crate::server::command_remote_write_tests::{deliver, device, disable_initiation};
use crate::server::cov_wire_test_support::*;
use crate::server::event_recipient_routing_tests::{address_recipient, destination_for};
use crate::server::remote_write_discovery_tests::{everywhere, i_am, next_who_is, targeted};
use crate::server::*;
use bacnet_encoding::constructed::decode_event_notification;
use bacnet_types::constructed::BACnetRecipient;

/// How long a probe waits for the I-Am: the APDU timeout.
const WAIT: Duration = Duration::from_secs(3);
/// Device 9's MAC, from which it answers.
const DEVICE_9: [u8; 6] = [10, 0, 0, 9, 0xBA, 0xC0];
/// The peer the class names by address.
const OTHER: [u8; 6] = [10, 0, 0, 7, 0xBA, 0xC0];

/// A server whose AV-1 alarms to Device 9, confirmed or not, as process 9,
/// and to [`OTHER`] as process 7.
async fn start(confirmed: bool) -> Harness {
    Harness::start_with(ServerConfig::default(), move |db| {
        let mut nc = bacnet_objects::notification_class::NotificationClass::new(0, "NC-0").unwrap();
        let mut to_device = destination_for(BACnetRecipient::Device(device(9)), confirmed);
        to_device.process_identifier = 9;
        let mut to_other = destination_for(address_recipient(0, &OTHER), false);
        to_other.process_identifier = 7;
        nc.add_destination(to_device).unwrap();
        nc.add_destination(to_other).unwrap();
        db.add(Box::new(nc)).unwrap();
        let object = db.get_mut(&av1()).unwrap();
        for (property, value) in [
            (PropertyIdentifier::HIGH_LIMIT, 80.0f32),
            (PropertyIdentifier::LOW_LIMIT, 0.0),
            (PropertyIdentifier::DEADBAND, 1.0),
        ] {
            object
                .write_property(property, None, PropertyValue::Real(value), None)
                .unwrap();
        }
        for (property, unused_bits, bits) in [
            (PropertyIdentifier::LIMIT_ENABLE, 6, 0xC0),
            (PropertyIdentifier::EVENT_ENABLE, 5, 0xE0),
        ] {
            object
                .write_property(
                    property,
                    None,
                    PropertyValue::BitString {
                        unused_bits,
                        data: vec![bits],
                    },
                    None,
                )
                .unwrap();
        }
    })
    .await
}

/// `(MAC, process identifier, confirmed)` of every event notification sent.
fn notifications(h: &Harness) -> Vec<(Vec<u8>, u32, bool)> {
    h.server
        .test_network()
        .transport()
        .sent()
        .frames()
        .into_iter()
        .filter_map(|frame| {
            let (request, confirmed) = match frame.apdu() {
                Apdu::UnconfirmedRequest(request)
                    if request.service_choice
                        == UnconfirmedServiceChoice::UNCONFIRMED_EVENT_NOTIFICATION =>
                {
                    (request.service_request, false)
                }
                Apdu::ConfirmedRequest(request)
                    if request.service_choice
                        == ConfirmedServiceChoice::CONFIRMED_EVENT_NOTIFICATION =>
                {
                    (request.service_request, true)
                }
                _ => return None,
            };
            let notification = decode_event_notification(&request).unwrap();
            Some((
                frame.mac.to_vec(),
                notification.process_identifier,
                confirmed,
            ))
        })
        .collect()
}

/// `device_recipient_unbound` and `confirmed_unanswered`.
fn counted(h: &Harness) -> (u64, u64) {
    let counters = h.server.event_notification_counters();
    (
        counters.device_recipient_unbound,
        counters.confirmed_unanswered,
    )
}

#[tokio::test(start_paused = true)]
async fn an_unbound_recipient_that_answers_gets_the_notification_and_the_others_do_not_wait() {
    let mut h = start(false).await;
    h.write_local(85.0).await;
    // The other recipient has its notification at once, and Device 9 is
    // looked for everywhere, since the server has never heard from it.
    assert_eq!(notifications(&h), vec![(OTHER.to_vec(), 7, false)]);
    assert_eq!(next_who_is(&h).await, (everywhere(), targeted(9)));

    tokio::time::advance(WAIT / 2).await;
    deliver(&h, &i_am(9), &DEVICE_9, None).await;
    h.settle().await;
    assert_eq!(
        notifications(&h),
        vec![(OTHER.to_vec(), 7, false), (DEVICE_9.to_vec(), 9, false)]
    );
    assert_eq!(counted(&h), (0, 0));

    // The binding the I-Am made serves the next notification directly.
    h.write_local(50.0).await;
    h.settle().await;
    assert_eq!(notifications(&h).len(), 4);
    assert!(next_who_is_none(&h));
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_silent_recipient_is_skipped_and_counted_once_with_one_who_is() {
    let mut h = start(false).await;
    h.write_local(85.0).await;
    assert_eq!(next_who_is(&h).await, (everywhere(), targeted(9)));
    // Nothing is counted while the probe is out.
    tokio::time::sleep(WAIT - Duration::from_millis(1)).await;
    assert_eq!(counted(&h), (0, 0));
    tokio::time::sleep(Duration::from_millis(2)).await;
    assert_eq!(counted(&h), (1, 0));
    assert_eq!(notifications(&h), vec![(OTHER.to_vec(), 7, false)]);

    // Within the minute after a Who-Is that drew nothing, the next
    // notification asks again for nothing: it skips Device 9 at once.
    h.write_local(50.0).await;
    h.settle().await;
    assert!(next_who_is_none(&h));
    assert_eq!(counted(&h), (2, 0));
    assert_eq!(notifications(&h).len(), 2);
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_confirmed_notification_after_the_i_am_counts_as_any_other() {
    let mut h = start(true).await;
    h.write_local(85.0).await;
    next_who_is(&h).await;
    deliver(&h, &i_am(9), &DEVICE_9, None).await;
    h.settle().await;
    assert_eq!(
        notifications(&h),
        vec![(OTHER.to_vec(), 7, false), (DEVICE_9.to_vec(), 9, true)]
    );
    // Device 9 never acknowledges it: after the last retry it counts as
    // unanswered, not as a recipient with no binding.
    tokio::time::sleep(WAIT * 5).await;
    assert_eq!(notifications(&h).len(), 2 + 3);
    assert_eq!(counted(&h), (0, 1));
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn nothing_is_sent_under_disable_initiation() {
    // Restricted from the start: no Who-Is, no notification.
    let mut h = start(false).await;
    disable_initiation(&h);
    h.write_local(85.0).await;
    h.settle().await;
    assert!(next_who_is_none(&h));
    assert!(notifications(&h).is_empty());
    assert_eq!(counted(&h), (0, 0));
    h.server.stop().await.unwrap();

    // Restricted while the notification waits: the I-Am binds the device,
    // but nothing goes to it and nothing is counted.
    let mut h = start(false).await;
    h.write_local(85.0).await;
    next_who_is(&h).await;
    disable_initiation(&h);
    deliver(&h, &i_am(9), &DEVICE_9, None).await;
    h.settle().await;
    tokio::time::sleep(WAIT * 2).await;
    assert_eq!(notifications(&h), vec![(OTHER.to_vec(), 7, false)]);
    assert_eq!(counted(&h), (0, 0));
    h.server.stop().await.unwrap();
}

/// Whether no Who-Is has been sent since the last one taken.
fn next_who_is_none(h: &Harness) -> bool {
    crate::server::remote_write_discovery_tests::who_is_sent(h).is_empty()
}
