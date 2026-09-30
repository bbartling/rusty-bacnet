//! Timestamped COV-multiple reports carry each change's commit time (#856).
//!
//! The transport advances the Device clock when it sends the WriteProperty
//! SimpleACK. The server always sends that response after the mutation and
//! before its COV fanout, so preparation time differs from commit time without
//! any production hook.
use super::cov_wire_test_support::*;
use super::*;
use bacnet_objects::analog::AnalogValueObject;

#[tokio::test]
async fn initial_report_carries_admission_time() {
    let mut h = Harness::start(ServerConfig::default()).await;
    h.set_clock(1);
    *h.after_ack.lock().unwrap() = Some(at(2));
    h.subscribe(false).await;
    let initial = h.notification().await;
    assert_eq!(pv_rows(&initial), vec![(real(0.0), Some(time(1)))]);
    assert!(rows(&initial)
        .iter()
        .all(|(_, _, time_of_change)| *time_of_change == Some(time(1))));
    assert_eq!(envelope(&initial), Some((at(1).local_date, time(1))));
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn write_property_change_reports_commit_time_not_preparation_time() {
    for confirmed in [false, true] {
        let mut h = Harness::start(ServerConfig::default()).await;
        h.subscribe(confirmed).await;
        h.notification().await;
        if confirmed {
            h.ack().await;
            h.settle().await;
        }
        h.set_clock(10);
        h.write_pv(42.0, 20).await;
        let report = h.notification().await;
        assert_eq!(
            pv_rows(&report),
            vec![(real(42.0), Some(time(10)))],
            "confirmed={confirmed}"
        );
        assert!(rows(&report)
            .iter()
            .all(|(_, _, time_of_change)| *time_of_change == Some(time(10))));
        assert_eq!(envelope(&report), Some((at(10).local_date, time(10))));
        assert_eq!(
            *h.clock.0.lock().unwrap(),
            at(20),
            "prepared after the clock moved"
        );
        h.server.stop().await.unwrap();
    }
}

#[tokio::test]
async fn changes_held_while_notifications_are_suppressed_are_all_reported_in_order() {
    let mut h = Harness::start(ServerConfig::default()).await;
    h.subscribe(false).await;
    h.notification().await;
    // DISABLE_INITIATION suppresses notifications but not local changes.
    h.server.comm_state.store(2, Ordering::Release);
    h.set_clock(11);
    h.write_local(10.0).await;
    h.set_clock(12);
    h.write_local(20.0).await;
    h.no_notification().await;
    h.server.comm_state.store(0, Ordering::Release);
    h.set_clock(13);
    h.write_local(10.0).await;
    let report = h.notification().await;
    assert_eq!(
        pv_rows(&report),
        vec![
            (real(10.0), Some(time(11))),
            (real(20.0), Some(time(12))),
            (real(10.0), Some(time(13))),
        ],
        "A-B-A history is conveyed, each change at its own time"
    );
    let flags: Vec<_> = rows(&report)
        .into_iter()
        .filter(|(property, _, _)| *property == SF)
        .map(|(_, _, time_of_change)| time_of_change)
        .collect();
    assert_eq!(flags, vec![Some(time(11)), Some(time(12)), Some(time(13))]);
    assert_eq!(envelope(&report), Some((at(13).local_date, time(13))));
    h.server.stop().await.unwrap();
}

#[tokio::test]
async fn failed_send_keeps_changes_for_the_next_notification() {
    let mut h = Harness::start(ServerConfig::default()).await;
    h.subscribe(false).await;
    h.notification().await;
    h.fail_notifications.store(true, Ordering::Release);
    h.set_clock(21);
    h.write_local(5.0).await;
    h.no_notification().await;
    h.fail_notifications.store(false, Ordering::Release);
    h.set_clock(22);
    h.write_local(6.0).await;
    let report = h.notification().await;
    assert_eq!(
        pv_rows(&report),
        vec![(real(5.0), Some(time(21))), (real(6.0), Some(time(22)))]
    );
    // Retired once sent: an unchanged fanout conveys nothing further.
    h.set_clock(23);
    h.write_local(6.0).await;
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

#[tokio::test]
async fn full_history_drops_the_oldest_changes_and_counts_them() {
    // 206-octet APDU: the context holds three PV + Status_Flags changes.
    let mut h = Harness::start(ServerConfig {
        max_apdu_length: 206,
        ..ServerConfig::default()
    })
    .await;
    h.subscribe(false).await;
    h.notification().await;
    h.server.comm_state.store(2, Ordering::Release);
    for (second, value) in [(31, 1.0), (32, 2.0), (33, 3.0), (34, 4.0), (35, 5.0)] {
        h.set_clock(second);
        h.write_local(value).await;
    }
    assert_eq!(h.server.cov_counters().timed_changes_dropped, 2);
    h.server.comm_state.store(0, Ordering::Release);
    h.set_clock(36);
    h.write_local(6.0).await;
    let report = h.notification().await;
    assert_eq!(
        pv_rows(&report),
        vec![
            (real(4.0), Some(time(34))),
            (real(5.0), Some(time(35))),
            (real(6.0), Some(time(36))),
        ],
        "the newest changes survive, oldest first"
    );
    assert_eq!(h.server.cov_counters().timed_changes_dropped, 3);
    h.server.stop().await.unwrap();
}

/// Hold-off after a failed confirmed report with a 10 ms retry timeout: one
/// full retry cycle, the timeout times the first attempt and every retry.
const HOLD_OFF: Duration = Duration::from_millis(10 * (DEFAULT_APDU_RETRIES as u64 + 1));

#[tokio::test(start_paused = true)]
async fn confirmed_changes_retire_once_acknowledged() {
    let mut h = Harness::start(ServerConfig::default()).await;
    h.subscribe(true).await;
    h.notification().await;
    h.ack().await;
    h.settle().await;
    h.set_clock(41);
    h.write_local(1.0).await;
    assert_eq!(
        pv_rows(&h.notification().await),
        vec![(real(1.0), Some(time(41)))]
    );
    // Captured while that report is outstanding, so it waits (#896).
    h.set_clock(42);
    h.write_local(2.0).await;
    h.no_notification().await;
    // The Ack retires 1.0 and the held change follows without another write.
    h.ack().await;
    assert_eq!(
        pv_rows(&h.notification().await),
        vec![(real(2.0), Some(time(42)))]
    );
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn confirmed_changes_unacknowledged_return_for_the_next_report() {
    let mut h = Harness::start(ServerConfig {
        cov_retry_timeout_ms: 10,
        ..ServerConfig::default()
    })
    .await;
    h.subscribe(true).await;
    h.notification().await;
    h.ack().await;
    h.settle().await;
    h.set_clock(45);
    h.write_local(5.0).await;
    h.notification().await;
    // Transmitted with every retry but never acknowledged; then the context
    // holds off for one retry cycle (#896).
    h.workers_idle().await;
    tokio::time::sleep(HOLD_OFF).await;
    h.set_clock(46);
    h.write_local(6.0).await;
    assert_eq!(
        pv_rows(&h.notification().await),
        vec![(real(5.0), Some(time(45))), (real(6.0), Some(time(46)))]
    );
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn confirmed_changes_never_transmitted_return_for_the_next_report() {
    let mut h = Harness::start(ServerConfig {
        cov_retry_timeout_ms: 10,
        ..ServerConfig::default()
    })
    .await;
    h.subscribe(true).await;
    h.notification().await;
    h.ack().await;
    h.settle().await;
    h.fail_notifications.store(true, Ordering::Release);
    h.set_clock(43);
    h.write_local(3.0).await;
    h.workers_idle().await;
    tokio::time::sleep(HOLD_OFF).await;
    h.fail_notifications.store(false, Ordering::Release);
    h.set_clock(44);
    h.write_local(4.0).await;
    assert_eq!(
        pv_rows(&h.notification().await),
        vec![(real(3.0), Some(time(43))), (real(4.0), Some(time(44)))]
    );
    h.server.stop().await.unwrap();
}

/// AV-1 alarms above 80 and reports through Notification Class 0, whose
/// local-broadcast recipient makes the event notification observable.

#[tokio::test]
async fn alarm_status_change_carries_its_transition_time() {
    let mut h = Harness::start_with(ServerConfig::default(), high_limit_alarm).await;
    h.subscribe(false).await;
    h.notification().await;
    h.set_clock(40);
    // The event notification goes out before COV fanout; move the clock then.
    *h.after_broadcast.lock().unwrap() = Some(at(50));
    h.write_local(90.0).await;
    let report = h.notification().await;
    assert_eq!(
        *h.clock.0.lock().unwrap(),
        at(50),
        "event notification was sent"
    );
    let flags: Vec<_> = rows(&report)
        .into_iter()
        .filter(|(property, _, _)| *property == SF)
        .collect();
    assert_eq!(flags.len(), 2, "normal then in-alarm flags: {flags:?}");
    assert_ne!(
        flags[0].1, flags[1].1,
        "the transition changed Status_Flags"
    );
    assert!(
        flags
            .iter()
            .all(|(_, _, time_of_change)| *time_of_change == Some(time(40))),
        "both captured when committed, not when prepared: {flags:?}"
    );
    assert_eq!(envelope(&report), Some((at(40).local_date, time(40))));
    h.server.stop().await.unwrap();
}

fn av2() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 2).unwrap()
}

#[tokio::test]
async fn any_notification_to_the_context_conveys_every_pending_timestamped_change() {
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        db.add(Box::new(AnalogValueObject::new(2, "AV-2", 62).unwrap()))
            .unwrap();
    })
    .await;
    h.subscribe_specs(
        false,
        vec![(av1(), vec![(PV, true)]), (av2(), vec![(PV, true)])],
    )
    .await;
    h.notification().await;
    h.server.comm_state.store(2, Ordering::Release);
    h.set_clock(51);
    h.write_local_to(av1(), 11.0).await;
    h.no_notification().await;
    h.server.comm_state.store(0, Ordering::Release);
    h.set_clock(52);
    h.write_local_to(av2(), 12.0).await;
    let report = h.notification().await;
    let items: Vec<_> = report
        .list_of_cov_notifications
        .iter()
        .map(|item| {
            let pv: Vec<_> = item
                .list_of_values
                .iter()
                .filter(|value| value.property_identifier == PV)
                .map(|value| (value.value.clone(), value.time_of_change))
                .collect();
            (item.monitored_object_identifier, pv)
        })
        .collect();
    assert!(
        items.contains(&(av1(), vec![(real(11.0), Some(time(51)))])),
        "AV-1's held change travels with AV-2's report: {items:?}"
    );
    assert!(items.contains(&(av2(), vec![(real(12.0), Some(time(52)))])));
    assert_eq!(envelope(&report), Some((at(52).local_date, time(52))));
    // Retired with that notification.
    h.set_clock(53);
    h.write_local_to(av2(), 12.0).await;
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

#[tokio::test]
async fn an_explicit_untimestamped_selector_is_never_repeated_as_history() {
    let mut h = Harness::start(ServerConfig::default()).await;
    h.subscribe_specs(false, vec![(av1(), vec![(PV, true), (SF, false)])])
        .await;
    h.notification().await;
    h.server.comm_state.store(2, Ordering::Release);
    h.set_clock(54);
    h.write_local(10.0).await;
    h.set_clock(55);
    h.write_local(20.0).await;
    h.server.comm_state.store(0, Ordering::Release);
    h.set_clock(56);
    h.write_local(30.0).await;
    let report = h.notification().await;
    assert_eq!(
        pv_rows(&report),
        vec![
            (real(10.0), Some(time(54))),
            (real(20.0), Some(time(55))),
            (real(30.0), Some(time(56))),
        ]
    );
    let flags: Vec<_> = rows(&report)
        .into_iter()
        .filter(|(property, _, _)| *property == SF)
        .collect();
    // One current row only. It still carries the timestamped companion's time
    // because the unchanged explicit selector did not qualify (the existing
    // #823 rule; tracked as a #856 follow-up).
    assert_eq!(
        flags.iter().map(|(_, _, time)| *time).collect::<Vec<_>>(),
        vec![Some(time(56))],
        "Status_Flags is not timestamped history: {flags:?}"
    );
    h.server.stop().await.unwrap();
}
