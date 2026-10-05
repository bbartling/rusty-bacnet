//! A Channel's members are written side by side, each when its own
//! Execution_Delay is up, so a member in another device that waits for its
//! answer holds back no other member (Clause 12.53.12, #1343). Requests in
//! other devices wait in the server's queues: one at a time per device, and
//! at most 32 across the server (`command_lists::remote_slots`).
//!
//! CH-5 (channel 21) writes AO-1 in Device 9 at once and the local AO-2
//! 100 ms after the distribution starts. CH-10 (channel 26) writes the
//! Present_Values of AO-1 to AO-20 in Device 9, all at once. CH-11 and CH-12
//! (channels 27 and 28) each write AO-1 in twenty other devices, Devices 100
//! to 119 and 120 to 139. Every device is bound to the harness peer and
//! answers by hand. The clock is paused.
use super::channel_remote_write_tests::{
    answer_reads, error, next_request, reliability, remote_output, start_with,
};
use super::channel_wire_tests::{ch, channel, settled, write_channel, write_status};
use super::command_action_wire_tests::{ao, read_db, slot8};
use super::command_remote_write_tests::{ack, device, remote_write, sent_writes};
use super::command_runs::CommandRunner;
use super::cov_wire_test_support::*;
use super::*;
use bacnet_types::enums::{Reliability, WriteStatus};
use std::future::Future;

async fn start() -> Harness {
    let h = start_with(|db| {
        let members = (1..=20)
            .map(|output| (remote_output(9, output), 0))
            .collect();
        db.add(Box::new(channel(10, 26, members))).unwrap();
        for (instance, first) in [(11, 100), (12, 120)] {
            let members = (first..first + 20)
                .map(|device| (remote_output(device, 1), 0))
                .collect();
            db.add(Box::new(channel(instance, 16 + instance as u16, members)))
                .unwrap();
        }
    })
    .await;
    for instance in 100..140 {
        let binding = DeviceBinding::local(device(instance), PEER).unwrap();
        h.server
            .device_bindings
            .write()
            .await
            .insert_configured(binding, |_| false)
            .unwrap();
    }
    h
}

/// Wait for the WriteProperty requests sent next, at least one.
async fn next_writes(
    h: &Harness,
) -> Vec<(u8, bacnet_services::write_property::WritePropertyRequest)> {
    tokio::time::sleep(Duration::from_millis(10)).await;
    let sent = sent_writes(h);
    assert!(!sent.is_empty(), "a WriteProperty to another device");
    sent
}

#[tokio::test(start_paused = true)]
async fn a_silent_member_in_another_device_holds_back_no_member_here() {
    let mut h = start().await;
    let started = tokio::time::Instant::now();
    write_channel(&mut h, 5, &PropertyValue::Real(80.0), Some(8))
        .await
        .unwrap();
    answer_reads(&h, 1, &PropertyValue::Real(0.0)).await;
    // Device 9 never answers the write; AO-2 is written at its 100 ms all
    // the same.
    remote_write(&h).await;
    tokio::time::sleep_until(started + Duration::from_millis(99)).await;
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Null);
    tokio::time::sleep_until(started + Duration::from_millis(101)).await;
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Real(80.0));
    assert_eq!(write_status(&mut h, 5).await, WriteStatus::IN_PROGRESS);

    // Stopped while the write is outstanding, the run ends FAILED and the
    // write's invoke ID is free.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(h.server.notification_transactions.active_count(), 1);
    h.server.stop().await.unwrap();
    assert_eq!(
        read_db(&h, ch(5), PropertyIdentifier::WRITE_STATUS, None).await,
        PropertyValue::Enumerated(WriteStatus::FAILED.to_raw())
    );
    assert_eq!(
        read_db(&h, ch(5), PropertyIdentifier::RELIABILITY, None).await,
        PropertyValue::Enumerated(Reliability::PROCESS_ERROR.to_raw())
    );
    assert_eq!(h.server.notification_transactions.active_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_distribution_dropped_mid_write_frees_its_invoke_id_without_stop() {
    let h = start().await;
    // CH-5's run, made by hand: NULL needs no read, so AO-1's write is the
    // first request.
    let run = {
        let mut db = h.server.database().write().await;
        let channel = db.get_mut(&ch(5)).unwrap();
        channel
            .write_property(PV, None, PropertyValue::Null, Some(8))
            .unwrap();
        channel.take_command_run_internal().unwrap()
    };
    let runner = CommandRunner::for_server(&h.server);
    let mut running = Box::pin(crate::command_lists::execute(&runner, run));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    for _ in 0..100 {
        assert!(running.as_mut().poll(&mut cx).is_pending());
        if h.server.notification_transactions.active_count() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(h.server.notification_transactions.active_count(), 1);

    // Dropping the run, with the server still running, frees the write's
    // invoke ID itself and ends the run FAILED.
    drop(running);
    assert!(!h.server.notification_transactions.is_closed());
    assert_eq!(h.server.notification_transactions.active_count(), 0);
    assert_eq!(
        h.server.notification_transactions.run_slots().outstanding(),
        0
    );
    assert_eq!(
        read_db(&h, ch(5), PropertyIdentifier::WRITE_STATUS, None).await,
        PropertyValue::Enumerated(WriteStatus::FAILED.to_raw())
    );
    assert_eq!(
        read_db(&h, ch(5), PropertyIdentifier::RELIABILITY, None).await,
        PropertyValue::Enumerated(Reliability::PROCESS_ERROR.to_raw())
    );
}

#[tokio::test(start_paused = true)]
async fn reliability_takes_the_first_failure_to_finish_not_the_first_member() {
    let mut h = start().await;
    let value = PropertyValue::CharacterString("on".into());
    write_channel(&mut h, 5, &value, Some(8)).await.unwrap();
    // AO-1 there reads as a CharacterString, so the value goes on as one.
    answer_reads(&h, 1, &PropertyValue::CharacterString(String::new())).await;
    let (invoke_id, written) = next_request(&h, ao(1)).await;
    assert_eq!(written, [0x73, 0x00, b'o', b'n']);
    // AO-2 here holds a REAL, which a CharacterString can't become: a
    // configuration failure at 100 ms.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(write_status(&mut h, 5).await, WriteStatus::IN_PROGRESS);
    // AO-1, first in the list, fails later, as a process error.
    h.respond(error(invoke_id, ErrorCode::WRITE_ACCESS_DENIED))
        .await;
    assert_eq!(settled(&mut h, 5).await, WriteStatus::FAILED);
    assert_eq!(
        reliability(&mut h, 5).await,
        Reliability::CONFIGURATION_ERROR
    );
}

#[tokio::test(start_paused = true)]
async fn a_device_takes_one_request_from_the_runs_at_a_time() {
    let mut h = start().await;
    // NULL needs no read, so each member is one write; Device 9 gets them
    // one after the other.
    write_channel(&mut h, 10, &PropertyValue::Null, Some(8))
        .await
        .unwrap();
    let mut written = Vec::new();
    while written.len() < 20 {
        let [(invoke_id, request)]: [_; 1] = next_writes(&h).await.try_into().unwrap();
        assert_eq!(h.server.notification_transactions.active_count(), 1);
        written.push(request.object_identifier.instance_number());
        h.respond(ack(invoke_id)).await;
    }
    written.sort_unstable();
    assert_eq!(written, (1..=20).collect::<Vec<_>>());
    assert_eq!(settled(&mut h, 10).await, WriteStatus::SUCCESSFUL);
}

#[tokio::test(start_paused = true)]
async fn the_server_keeps_at_most_thirty_two_run_requests_outstanding() {
    let mut h = start().await;
    // Forty devices across two distributions: they share the server's 32.
    for instance in [11, 12] {
        write_channel(&mut h, instance, &PropertyValue::Null, Some(8))
            .await
            .unwrap();
    }
    let first = next_writes(&h).await;
    assert_eq!(first.len(), 32);
    assert_eq!(h.server.notification_transactions.active_count(), 32);
    let slots = h.server.notification_transactions.run_slots();
    assert_eq!(slots.outstanding(), 32);

    // Each answer lets one more go.
    for (invoke_id, _) in &first[..8] {
        h.respond(ack(*invoke_id)).await;
    }
    let rest = next_writes(&h).await;
    assert_eq!(rest.len(), 8);
    assert_eq!(h.server.notification_transactions.active_count(), 32);
    for (invoke_id, _) in first[8..].iter().chain(&rest) {
        h.respond(ack(*invoke_id)).await;
    }
    for instance in [11, 12] {
        assert_eq!(settled(&mut h, instance).await, WriteStatus::SUCCESSFUL);
    }
    assert_eq!(first.len() + rest.len(), 40);
    let slots = h.server.notification_transactions.run_slots();
    assert_eq!((slots.outstanding(), slots.devices()), (0, 0));
}

#[tokio::test(start_paused = true)]
async fn once_a_device_is_found_silent_its_queued_members_go_unsent() {
    let mut h = start().await;
    let started = tokio::time::Instant::now();
    write_channel(&mut h, 10, &PropertyValue::Null, Some(8))
        .await
        .unwrap();
    // AO-1's write goes four times under one invoke ID with no answer; the
    // nineteen members queued behind it at Device 9 then fail unsent.
    assert_eq!(settled(&mut h, 10).await, WriteStatus::FAILED);
    let took = started.elapsed();
    assert!(
        (Duration::from_secs(12)..Duration::from_millis(12_100)).contains(&took),
        "{took:?}"
    );
    let attempts = sent_writes(&h);
    assert_eq!(attempts.len(), 4);
    assert!(attempts.iter().all(|(id, _)| *id == attempts[0].0));
    assert_eq!(
        reliability(&mut h, 10).await,
        Reliability::COMMUNICATION_FAILURE
    );
    assert_eq!(h.server.notification_transactions.active_count(), 0);
}
