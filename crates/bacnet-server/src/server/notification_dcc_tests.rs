//! DeviceCommunicationControl and the confirmed notifications it stops
//! (Clause 16.1, #1327): COV and event notifications are withdrawn at the
//! attempt DCC would block, their invoke IDs freed there, and an answer that
//! has already taken the lease still ends them. Audit notifications are left
//! out of what DISABLE_INITIATION stops and never read the DCC state; their
//! tests are in `audit_dcc_tests.rs`.
//!
//! The clock is paused, and each attempt waits three seconds for its answer.
use std::sync::atomic::AtomicUsize;

use bacnet_endpoint_core::coordinator::LeaseToken;

use super::notification_transactions::run_notification_under_dcc;
use super::*;

const TIMEOUT: Duration = Duration::from_secs(3);
const PEER: [u8; 6] = [10, 0, 0, 9, 0xBA, 0xC0];
const DISABLE_INITIATION: u8 = 2;

type Outcome = Result<NotificationWorkerResult, InitiationRestricted>;

/// A confirmed COV notification to [`PEER`] with three retries, run in its
/// own task: the task, its count of sends and its lease.
fn spawn_notification(
    transactions: &NotificationTransactions,
    comm_state: &Arc<AtomicU8>,
) -> (JoinHandle<Outcome>, Arc<AtomicUsize>, LeaseToken) {
    let (operation, receiver) = transactions
        .reserve(
            canonical_direct_peer(&PEER),
            ConfirmedServiceChoice::CONFIRMED_COV_NOTIFICATION,
        )
        .unwrap();
    let token = operation.token();
    let sends = Arc::new(AtomicUsize::new(0));
    let (comm_state, counted) = (Arc::clone(comm_state), Arc::clone(&sends));
    let worker = tokio::spawn(async move {
        run_notification_under_dcc(operation, receiver, TIMEOUT, 3, &comm_state, |_| {
            counted.fetch_add(1, Ordering::AcqRel);
            std::future::ready(Ok::<(), ()>(()))
        })
        .await
    });
    (worker, sends, token)
}

/// Let spawned work run until it waits on the clock.
async fn settle() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn dcc_ends_an_outstanding_notification_at_its_next_retry_and_frees_its_lease() {
    let transactions = NotificationTransactions::new();
    let comm_state = Arc::new(AtomicU8::new(0));
    let (worker, sends, _) = spawn_notification(&transactions, &comm_state);
    settle().await;
    assert_eq!(sends.load(Ordering::Acquire), 1);
    let sent = tokio::time::Instant::now();
    comm_state.store(DISABLE_INITIATION, Ordering::Release);
    assert_eq!(worker.await.unwrap(), Err(InitiationRestricted));
    let ended = sent.elapsed();
    assert!(
        (TIMEOUT..TIMEOUT + Duration::from_millis(5)).contains(&ended),
        "{ended:?}"
    );
    assert_eq!(sends.load(Ordering::Acquire), 1, "the retry is not sent");
    assert_eq!(transactions.active_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn dcc_in_force_at_the_first_attempt_sends_nothing_and_frees_the_lease_at_once() {
    let transactions = NotificationTransactions::new();
    let comm_state = Arc::new(AtomicU8::new(DISABLE_INITIATION));
    let started = tokio::time::Instant::now();
    let (worker, sends, _) = spawn_notification(&transactions, &comm_state);
    assert_eq!(worker.await.unwrap(), Err(InitiationRestricted));
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_eq!(sends.load(Ordering::Acquire), 0);
    assert_eq!(transactions.active_count(), 0);
}

/// The answer took the lease before the retry timer fired and is still on its
/// way when DCC restricts initiation: the retry finds the lease claimed and
/// waits for that answer instead of being withdrawn.
#[tokio::test(start_paused = true)]
async fn an_answer_claimed_as_the_retry_timer_fires_still_ends_the_notification() {
    let transactions = NotificationTransactions::new();
    let comm_state = Arc::new(AtomicU8::new(0));
    let (worker, sends, token) = spawn_notification(&transactions, &comm_state);
    settle().await;
    let answer = transactions.claim_answer_for_test(token);
    comm_state.store(DISABLE_INITIATION, Ordering::Release);
    tokio::time::advance(TIMEOUT).await;
    settle().await;
    assert!(!worker.is_finished());
    answer.send(CovAckResult::Ack).unwrap();
    assert_eq!(worker.await.unwrap(), Ok(NotificationWorkerResult::Ack));
    assert_eq!(sends.load(Ordering::Acquire), 1);
    assert_eq!(transactions.active_count(), 0);
}
