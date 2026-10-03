//! A recipient aborting a confirmed EventNotification is the server of that
//! transaction, so its Abort has the server flag set (Clause 5.4). That Abort
//! ends the notification at once; one with the flag clear is refused (#1155).

use super::*;
use crate::server::EventNotificationCounters;
use bacnet_encoding::apdu::AbortPdu;
use bacnet_types::enums::AbortReason;

const TARGET: [u8; 6] = [192, 168, 1, 50, 0xBA, 0xC0];
const RETRY_TIMEOUT_MS: u64 = 100;

fn abort(invoke_id: u8, sent_by_server: bool) -> Apdu {
    Apdu::Abort(AbortPdu {
        sent_by_server,
        invoke_id,
        abort_reason: AbortReason::OTHER,
    })
}

#[tokio::test(start_paused = true)]
async fn recipient_abort_ends_a_confirmed_event_notification_without_retries() {
    let harness = Harness::new(
        vec![destination_for(address_recipient(0, &TARGET), true)],
        RETRY_TIMEOUT_MS,
    )
    .await;
    harness.distribute().await;
    let unicasts = harness.unicast_frames();
    assert_eq!(unicasts.len(), 1);
    assert_eq!(unicasts[0].0.as_slice(), &TARGET);
    let invoke_id = decode_confirmed(&unicasts[0].1).1.invoke_id;

    assert!(
        !harness
            .dispatch_terminal(&TARGET, None, abort(invoke_id, false))
            .await,
        "an Abort with the server flag clear is not the recipient's"
    );
    assert_eq!(harness.notification_transactions.active_count(), 1);
    assert!(
        harness
            .dispatch_terminal(&TARGET, None, abort(invoke_id, true))
            .await,
        "the recipient's Abort ends the transaction"
    );
    let finished = tokio::time::timeout(
        Duration::from_secs(5),
        harness.notification_transactions.join_next(),
    )
    .await
    .expect("the notification worker finishes");
    assert!(matches!(finished, Some(Ok(()))), "{finished:?}");

    // Let the whole retry budget pass: an aborted notification is never resent.
    tokio::time::sleep(Duration::from_millis(
        RETRY_TIMEOUT_MS * (u64::from(DEFAULT_APDU_RETRIES) + 1),
    ))
    .await;
    assert_eq!(
        harness.unicast_frames().len(),
        1,
        "no retry after the Abort"
    );
    assert!(harness.broadcast_frames().is_empty());
    // The refused Abort counts nothing; the recipient's counts as a
    // rejection, not as an unanswered notification (#1142).
    assert_eq!(
        harness.suppressions.snapshot(),
        EventNotificationCounters {
            confirmed_rejected: 1,
            ..EventNotificationCounters::default()
        }
    );
}
