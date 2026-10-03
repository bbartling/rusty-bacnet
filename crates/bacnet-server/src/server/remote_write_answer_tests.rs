//! Which answers end a remote write, and how (#1180): the write is made
//! through the server's run host directly, so each test sees the
//! [`RemoteWriteError`] it ends with.
//!
//! Device 9 is bound to the harness peer, and the write sets AO-1 there to
//! 80.0 at priority 8. The clock is paused, and the server's APDU timeout is
//! the default 3 seconds.
use super::command_action_wire_tests::{ao, write};
use super::command_remote_write_tests::{
    ack, deliver, device, disable_initiation, remote_write, sent_writes, start_local,
};
use super::command_runs::CommandRunner;
use super::cov_wire_test_support::*;
use super::*;
use crate::command_lists::RunHost;
use bacnet_types::constructed::BACnetActionCommand;
use tokio::task::JoinHandle;

/// Another device on the harness link, which has no lease of its own.
const STRANGER: [u8; 6] = [10, 0, 0, 6, 0xBA, 0xC0];

/// Start the write and wait for its request: the task and its invoke ID.
async fn start_write(h: &Harness) -> (JoinHandle<Result<(), RemoteWriteError>>, u8) {
    let runner = CommandRunner::for_server(&h.server);
    let command = BACnetActionCommand {
        device_identifier: Some(device(9)),
        ..write(ao(1), PropertyValue::Real(80.0), 8)
    };
    let task = tokio::spawn(async move { runner.write_remote(device(9), &command).await });
    let invoke_id = remote_write(h).await;
    (task, invoke_id)
}

fn error_for(invoke_id: u8, service_choice: ConfirmedServiceChoice) -> Apdu {
    Apdu::Error(ErrorPdu {
        invoke_id,
        service_choice,
        error_class: ErrorClass::PROPERTY,
        error_code: ErrorCode::WRITE_ACCESS_DENIED,
        error_data: Bytes::new(),
    })
}

#[tokio::test(start_paused = true)]
async fn remote_write_ignores_answers_from_another_peer_or_for_another_service() {
    let h = start_local().await;
    let (task, invoke_id) = start_write(&h).await;
    let write_property = ConfirmedServiceChoice::WRITE_PROPERTY;
    deliver(&h, &ack(invoke_id), &STRANGER, None).await;
    deliver(&h, &error_for(invoke_id, write_property), &STRANGER, None).await;
    let other_service = ConfirmedServiceChoice::CONFIRMED_COV_NOTIFICATION;
    deliver(&h, &error_for(invoke_id, other_service), &PEER, None).await;
    h.settle().await;
    assert!(!task.is_finished());
    assert_eq!(h.server.notification_transactions.active_count(), 1);

    deliver(&h, &ack(invoke_id), &PEER, None).await;
    assert_eq!(task.await.unwrap(), Ok(()));
    assert_eq!(h.server.notification_transactions.active_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn remote_write_reject_or_abort_ends_it_at_once_without_retries() {
    let h = start_local().await;
    let answers: [fn(u8) -> Apdu; 2] = [
        |invoke_id| {
            Apdu::Reject(RejectPdu {
                invoke_id,
                reject_reason: RejectReason::UNRECOGNIZED_SERVICE,
            })
        },
        |invoke_id| {
            Apdu::Abort(AbortPdu {
                sent_by_server: true,
                invoke_id,
                abort_reason: AbortReason::OTHER,
            })
        },
    ];
    for answer in answers {
        let (task, invoke_id) = start_write(&h).await;
        let sent = tokio::time::Instant::now();
        deliver(&h, &answer(invoke_id), &PEER, None).await;
        assert_eq!(task.await.unwrap(), Err(RemoteWriteError::Refused));
        assert!(sent.elapsed() < Duration::from_millis(100));
        assert_eq!(h.server.notification_transactions.active_count(), 0);
        tokio::time::sleep(Duration::from_secs(15)).await;
        assert!(sent_writes(&h).is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn remote_write_blocked_by_dcc_at_a_retry_ends_there_as_disabled() {
    let h = start_local().await;
    let (task, _) = start_write(&h).await;
    let sent = tokio::time::Instant::now();
    disable_initiation(&h);
    assert_eq!(task.await.unwrap(), Err(RemoteWriteError::Disabled));
    let ended = sent.elapsed();
    assert!(
        (Duration::from_millis(2_900)..Duration::from_millis(3_050)).contains(&ended),
        "{ended:?}"
    );
    assert_eq!(h.server.notification_transactions.active_count(), 0);
    assert!(sent_writes(&h).is_empty());
}
