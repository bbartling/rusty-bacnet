//! A Channel's members are written side by side, each when its own
//! Execution_Delay is up, so a member in another device that waits for its
//! answer holds back no other member (Clause 12.53.12, #1343).
//!
//! CH-5 (channel 21) writes AO-1 in Device 9 at once and the local AO-2
//! 100 ms after the distribution starts. CH-10 (channel 26) writes the
//! Present_Values of AO-1 to AO-20 in Device 9, all at once. Device 9 is bound
//! to the harness peer and answers by hand. The clock is paused.
use super::channel_remote_write_tests::{
    answer_reads, error, next_request, reliability, remote_output, start_with,
};
use super::channel_wire_tests::{ch, channel, settled, write_channel, write_status};
use super::command_action_wire_tests::{ao, read_db, slot8};
use super::command_remote_write_tests::{ack, remote_write, sent_writes};
use super::cov_wire_test_support::*;
use super::*;
use bacnet_types::enums::{Reliability, WriteStatus};

async fn start() -> Harness {
    start_with(|db| {
        let members = (1..=20)
            .map(|output| (remote_output(9, output), 0))
            .collect();
        db.add(Box::new(channel(10, 26, members))).unwrap();
    })
    .await
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
async fn a_distribution_keeps_at_most_sixteen_requests_outstanding_in_other_devices() {
    let mut h = start().await;
    // NULL needs no read, so each member is one write.
    write_channel(&mut h, 10, &PropertyValue::Null, Some(8))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    let first = sent_writes(&h);
    assert_eq!(first.len(), 16);
    assert_eq!(h.server.notification_transactions.active_count(), 16);

    // Each answer lets one more member go.
    for (invoke_id, _) in &first[..4] {
        h.respond(ack(*invoke_id)).await;
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
    let rest = sent_writes(&h);
    assert_eq!(rest.len(), 4);
    assert_eq!(h.server.notification_transactions.active_count(), 16);
    for (invoke_id, _) in first[4..].iter().chain(&rest) {
        h.respond(ack(*invoke_id)).await;
    }
    assert_eq!(settled(&mut h, 10).await, WriteStatus::SUCCESSFUL);
    let mut written: Vec<_> = first
        .iter()
        .chain(&rest)
        .map(|(_, request)| request.object_identifier.instance_number())
        .collect();
    written.sort_unstable();
    assert_eq!(written, (1..=20).collect::<Vec<_>>());
}
