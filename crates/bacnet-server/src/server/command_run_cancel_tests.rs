//! A `write_local` dropped after its write committed leaves no Command or
//! Channel busy (#1324). The write takes the run it queued under its database
//! guard but starts it only after the COV and event passes, so a caller that
//! drops the future in between (a timeout, a `select!`) lets go of a run
//! nothing has started. That run ends as if none of its writes were made, at
//! once if the database is free and otherwise as soon as it is, with no
//! `stop()`.
//!
//! Each test holds the COV table, so the write parks on it at a known point,
//! polls the write once by hand, and drops it there. The objects are those of
//! `command_run_stop_tests`: CMD-1's list 2 writes AO-2 with a 5-second post
//! delay, then AO-1, and CH-5 writes AO-2 200 ms after its Present_Value is
//! written. The clock is paused.
use super::channel_wire_tests::ch;
use super::command_action_wire_tests::{ao, cmd, idle, read_db, slot8};
use super::command_run_stop_tests::{channel_status, db_flags, db_state, objects, with_channel};
use super::cov_wire_test_support::*;
use super::*;
use bacnet_types::enums::{Reliability, WriteStatus};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

type Write<'a> = Pin<Box<dyn Future<Output = Result<(), Error>> + 'a>>;

/// `write_local` of `value` to `object`'s Present_Value, from the Device.
fn write_local<'a>(
    h: &'a Harness,
    object: &'a ObjectIdentifier,
    value: PropertyValue,
    priority: Option<u8>,
) -> Write<'a> {
    Box::pin(h.server.write_local(
        object,
        PV,
        None,
        value,
        priority,
        crate::LocalCommandSource::ServerDevice,
    ))
}

/// Run `write` until its first wait.
fn poll_once(write: &mut Write<'_>) -> Poll<Result<(), Error>> {
    write.as_mut().poll(&mut Context::from_waker(Waker::noop()))
}

/// CMD-1's In_Process, read through `db`.
fn in_process(db: &ObjectDatabase) -> PropertyValue {
    db.get(&cmd(1))
        .unwrap()
        .read_property(PropertyIdentifier::IN_PROCESS, None)
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn write_local_dropped_after_its_commit_ends_the_command_run_unsuccessful() {
    let h = Harness::start_with(ServerConfig::default(), objects).await;
    let table = Arc::clone(&h.server.cov_table).read_owned().await;
    let target = cmd(1);
    let mut write = write_local(&h, &target, PropertyValue::Unsigned(2), None);
    assert!(poll_once(&mut write).is_pending());
    // The write committed, let go of the database and waits to fan COV out.
    assert!(h.server.database().try_write().is_ok());
    assert_eq!(db_state(&h, 1).await, (true, false));

    drop(write);
    // Ended at once, before any of its writes and with no task to make them:
    // no `stop()`, no wait.
    assert_eq!(db_state(&h, 1).await, (false, false));
    assert_eq!(db_flags(&h, 2).await, [false, false]);
    assert!(h.server.request_tasks.is_empty());
    drop(table);
    h.settle().await;
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Null);
    // CMD-1 isn't busy: the next write runs its list.
    h.server
        .write_local(
            &target,
            PV,
            None,
            PropertyValue::Unsigned(1),
            None,
            crate::LocalCommandSource::ServerDevice,
        )
        .await
        .unwrap();
    idle(&h, 1).await;
    assert_eq!(slot8(&h, ao(1)).await, PropertyValue::Real(50.0));
}

#[tokio::test(start_paused = true)]
async fn write_local_dropped_while_the_database_is_busy_ends_the_run_once_it_is_free() {
    let h = Harness::start_with(ServerConfig::default(), objects).await;
    let table = Arc::clone(&h.server.cov_table).read_owned().await;
    let target = cmd(1);
    let mut write = write_local(&h, &target, PropertyValue::Unsigned(2), None);
    assert!(poll_once(&mut write).is_pending());
    // An application holds the database as the write is dropped, so the run
    // can't end then; it ends once the application lets go.
    let held = Arc::clone(h.server.database()).read_owned().await;
    drop(write);
    assert_eq!(in_process(&held), PropertyValue::Boolean(true));
    drop(held);
    drop(table);
    h.settle().await;
    assert_eq!(db_state(&h, 1).await, (false, false));
    assert_eq!(db_flags(&h, 2).await, [false, false]);
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Null);
}

#[tokio::test(start_paused = true)]
async fn write_local_dropped_inside_its_database_guard_ends_the_distribution_failed() {
    let h = Harness::start_with(ServerConfig::default(), with_channel).await;
    // With the table held for writing, the write parks on it under its own
    // database guard, right after taking the distribution it queued.
    let table = Arc::clone(&h.server.cov_table).write_owned().await;
    let target = ch(5);
    let mut write = write_local(&h, &target, PropertyValue::Real(12.0), Some(8));
    assert!(poll_once(&mut write).is_pending());
    assert!(h.server.database().try_read().is_err());

    drop(write);
    drop(table);
    h.settle().await;
    assert_eq!(channel_status(&h).await, WriteStatus::FAILED);
    assert_eq!(
        read_db(&h, ch(5), PropertyIdentifier::RELIABILITY, None).await,
        PropertyValue::Enumerated(Reliability::PROCESS_ERROR.to_raw())
    );
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Null);
}

#[tokio::test(start_paused = true)]
async fn write_local_dropped_after_its_commit_ends_the_distribution_failed() {
    let h = Harness::start_with(ServerConfig::default(), with_channel).await;
    let table = Arc::clone(&h.server.cov_table).read_owned().await;
    let target = ch(5);
    let mut write = write_local(&h, &target, PropertyValue::Real(12.0), Some(8));
    assert!(poll_once(&mut write).is_pending());
    assert!(h.server.database().try_write().is_ok());
    assert_eq!(channel_status(&h).await, WriteStatus::IN_PROGRESS);

    drop(write);
    assert_eq!(channel_status(&h).await, WriteStatus::FAILED);
    drop(table);
    h.settle().await;
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Null);
}
