//! Background commits reach COV subscribers without another write (#889).
//!
//! Periodic intrinsic reporting, fault detection and schedule writes change
//! objects on their own timers. Each commit fans COV out as a network write
//! does, so ordinary and timestamped subscribers hear of it. Time is paused, and
//! Tokio advances it whenever the test waits.
use super::cov_wire_test_support::*;
use super::*;
use bacnet_objects::analog::AnalogValueObject;
use bacnet_objects::schedule::ScheduleObject;
use bacnet_services::cov::COVNotificationRequest;
use bacnet_types::constructed::BACnetObjectPropertyReference;
use bacnet_types::enums::ObjectType;

const IN_ALARM: u8 = 0x80;
const FAULT: u8 = 0x40;

/// The Status_Flags bits of an application-tagged BIT STRING value.
fn flags(value: &[u8]) -> u8 {
    assert_eq!(&value[..2], &[0x82, 0x04], "four-bit Status_Flags");
    value[2]
}

fn cov_flags(notification: &COVNotificationRequest) -> u8 {
    let value = notification
        .list_of_values
        .iter()
        .find(|value| value.property_identifier == SF)
        .expect("Status_Flags reported with Present_Value");
    flags(&value.value)
}

fn cov_value(notification: &COVNotificationRequest) -> Vec<u8> {
    notification
        .list_of_values
        .iter()
        .find(|value| value.property_identifier == PV)
        .expect("Present_Value reported")
        .value
        .clone()
}

/// The high-limit alarm, confirmed only after a two-second Time_Delay.
fn delayed_high_limit_alarm(db: &mut ObjectDatabase) {
    high_limit_alarm(db);
    db.get_mut(&av1())
        .unwrap()
        .write_property(
            PropertyIdentifier::TIME_DELAY,
            None,
            PropertyValue::Unsigned(2),
            None,
        )
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_delayed_alarm_reaches_ordinary_and_timestamped_subscribers_without_another_write() {
    let mut h = Harness::start_with(ServerConfig::default(), delayed_high_limit_alarm).await;
    h.subscribe_cov().await;
    assert_eq!(cov_flags(&h.cov_notification().await), 0);
    h.subscribe(false).await;
    h.notification().await;

    h.set_clock(10);
    h.write_local(90.0).await;
    // The write only starts the Time_Delay countdown.
    assert_eq!(cov_flags(&h.cov_notification().await), 0);
    h.notification().await;

    // The one-second task confirms the alarm; nothing else is written.
    h.set_clock(20);
    let ordinary = h.cov_notification().await;
    assert_eq!(cov_flags(&ordinary) & IN_ALARM, IN_ALARM);
    let timed = h.notification().await;
    let alarm: Vec<_> = rows(&timed)
        .into_iter()
        .filter(|(property, value, _)| *property == SF && flags(value) & IN_ALARM != 0)
        .collect();
    assert_eq!(alarm.len(), 1, "one in-alarm change: {alarm:?}");
    assert_eq!(alarm[0].2, Some(time(20)), "stamped when committed");
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn fault_detection_reaches_subscribers_without_another_write() {
    let config = ServerConfig {
        enable_fault_detection: true,
        ..ServerConfig::default()
    };
    let mut h = Harness::start_with(config, |db| {
        db.remove(&av1()).unwrap();
        let mut object = AnalogValueObject::new(1, "AV-1", 62).unwrap();
        object.configure_fault_out_of_range(0.0, 100.0).unwrap();
        db.add(Box::new(object)).unwrap();
    })
    .await;
    h.subscribe_cov().await;
    h.cov_notification().await;

    h.write_local(150.0).await;
    let written = h.cov_notification().await;
    assert_eq!(
        cov_flags(&written) & FAULT,
        0,
        "reliability not yet evaluated"
    );

    // Fault detection runs every ten seconds.
    tokio::time::sleep(Duration::from_secs(10)).await;
    let detected = h.cov_notification().await;
    assert_eq!(cov_flags(&detected) & FAULT, FAULT);
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_schedule_write_reaches_subscribers() {
    let schedule = ObjectIdentifier::new(ObjectType::SCHEDULE, 1).unwrap();
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        let mut object = ScheduleObject::new(1, "SCH-1", PropertyValue::Real(0.0)).unwrap();
        object
            .add_object_property_reference(BACnetObjectPropertyReference::new(av1(), PV.to_raw()));
        db.add(Box::new(object)).unwrap();
    })
    .await;
    h.subscribe_cov().await;
    h.cov_notification().await;

    // Change what the schedule commands directly, so only its next evaluation
    // writes AV-1.
    h.server
        .database()
        .write()
        .await
        .get_mut(&schedule)
        .unwrap()
        .write_property(
            PropertyIdentifier::SCHEDULE_DEFAULT,
            None,
            PropertyValue::Real(42.0),
            None,
        )
        .unwrap();
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(cov_value(&h.cov_notification().await), real(42.0));
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn an_alarm_the_write_already_reported_is_not_repeated_by_the_tick() {
    // Without a Time_Delay the write itself confirms and reports the alarm.
    let mut h = Harness::start_with(ServerConfig::default(), high_limit_alarm).await;
    h.subscribe_cov().await;
    h.cov_notification().await;
    h.write_local(90.0).await;
    assert_eq!(cov_flags(&h.cov_notification().await) & IN_ALARM, IN_ALARM);
    tokio::time::sleep(Duration::from_secs(3)).await;
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn dcc_still_suppresses_background_cov() {
    let mut h = Harness::start_with(ServerConfig::default(), delayed_high_limit_alarm).await;
    h.subscribe_cov().await;
    h.cov_notification().await;
    h.write_local(90.0).await;
    h.cov_notification().await;
    h.server.comm_state.store(2, Ordering::Release);
    tokio::time::sleep(Duration::from_secs(3)).await;
    h.no_notification().await;
    h.server.stop().await.unwrap();
}
