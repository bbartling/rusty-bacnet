//! DeviceCommunicationControl restricting initiation while a confirmed
//! EventNotification is outstanding ends it at its next retry (Clause 16.1,
//! #1327): the retry is not sent and the invoke ID is freed there. Like a
//! notification DCC stops before its first send, it moves no counter, leaves
//! Acked_Transitions as the transition set it, and is not sent again once
//! initiation is enabled.

use super::*;
use crate::server::EventNotificationCounters;

const TARGET: [u8; 6] = [192, 168, 1, 50, 0xBA, 0xC0];
const TIMEOUT: Duration = Duration::from_secs(3);

async fn acked_transitions(harness: &Harness, oid: &ObjectIdentifier) -> PropertyValue {
    harness
        .db
        .read()
        .await
        .get(oid)
        .unwrap()
        .read_property(PropertyIdentifier::ACKED_TRANSITIONS, None)
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn dcc_ends_an_outstanding_confirmed_event_notification_at_its_next_retry() {
    let harness = Harness::new(Vec::new(), TIMEOUT.as_millis() as u64).await;
    // TO_OFFNORMAL needs an acknowledgment, so the transition clears its bit.
    let mut nc = NotificationClass::new(0, "NC-0").unwrap();
    nc.priority = [255, 255, 255];
    nc.ack_required = bacnet_types::bitstring::EventTransitionBits::TO_OFFNORMAL;
    nc.add_destination(destination_for(address_recipient(0, &TARGET), true))
        .unwrap();
    harness.db.write().await.add(Box::new(nc)).unwrap();
    let oid = harness.distribute_committed().await;
    let sent = tokio::time::Instant::now();
    assert_eq!(harness.unicast_frames().len(), 1);
    let acked = acked_transitions(&harness, &oid).await;
    assert_eq!(
        acked,
        PropertyValue::BitString {
            unused_bits: 5,
            data: vec![0x60],
        }
    );

    harness.comm_state.store(2, Ordering::Release); // DISABLE_INITIATION
    let finished = tokio::time::timeout(
        Duration::from_secs(60),
        harness.notification_transactions.join_next(),
    )
    .await
    .expect("the notification worker finishes");
    assert!(matches!(finished, Some(Ok(()))), "{finished:?}");
    let ended = sent.elapsed();
    assert!(
        (TIMEOUT..TIMEOUT + Duration::from_millis(5)).contains(&ended),
        "ended {ended:?} after the notification"
    );
    assert_eq!(harness.notification_transactions.active_count(), 0);
    assert_eq!(harness.unicast_frames().len(), 1, "the retry is not sent");
    assert_eq!(
        harness.suppressions.snapshot(),
        EventNotificationCounters::default()
    );
    assert_eq!(acked_transitions(&harness, &oid).await, acked);

    // Enabled again: the withdrawn notification is not sent again.
    harness.comm_state.store(0, Ordering::Release);
    tokio::time::advance(TIMEOUT * 4).await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert_eq!(harness.unicast_frames().len(), 1);
}
