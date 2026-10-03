//! AddListElement and RemoveListElement run the per-write event evaluation,
//! as WriteProperty does (#1305 review). An Alarm_Values edit that puts the
//! watched value in or out of alarm transitions at once with Time_Delay 0,
//! not at the periodic task's second tick, and the transition's
//! Status_Flags change still reaches a SubscribeCOV subscriber.
//!
//! The clock is paused, so the periodic task ticks only when a test sleeps
//! past a second; `settle` stays well inside the first one.
use super::cov_wire_test_support::*;
use super::*;
use bacnet_objects::access_control::{AccessDoorObject, AccessZoneObject};
use bacnet_objects::multistate::MultiStateInputObject;
use bacnet_services::cov::SubscribeCOVRequest;
use bacnet_services::list_manipulation::ListElementRequest;
use bacnet_types::enums::EventState;

const ADD: ConfirmedServiceChoice = ConfirmedServiceChoice::ADD_LIST_ELEMENT;
const REMOVE: ConfirmedServiceChoice = ConfirmedServiceChoice::REMOVE_LIST_ELEMENT;

fn zone1() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::ACCESS_ZONE, 1).unwrap()
}

fn msi1() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::MULTI_STATE_INPUT, 1).unwrap()
}

/// An AddListElement or RemoveListElement body for `object`'s Alarm_Values.
fn alarm_values(object: ObjectIdentifier, elements: &[u8]) -> BytesMut {
    list_body(object, PropertyIdentifier::ALARM_VALUES, elements)
}

/// An AddListElement or RemoveListElement body for `object`'s `list`.
fn list_body(object: ObjectIdentifier, list: PropertyIdentifier, elements: &[u8]) -> BytesMut {
    let mut body = BytesMut::new();
    ListElementRequest {
        object_identifier: object,
        property_identifier: list,
        property_array_index: None,
        list_of_elements: elements.to_vec(),
    }
    .encode(&mut body)
    .unwrap();
    body
}

async fn event_state(h: &Harness, object: ObjectIdentifier) -> EventState {
    match h
        .server
        .database()
        .read()
        .await
        .get(&object)
        .unwrap()
        .read_property(PropertyIdentifier::EVENT_STATE, None)
        .unwrap()
    {
        PropertyValue::Enumerated(raw) => EventState::from_raw(raw),
        other => panic!("Event_State read {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn alarm_values_list_edits_move_a_zone_at_once() {
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        // Six inside a zone whose upper limit is five: ABOVE_UPPER_LIMIT (4).
        let mut zone = AccessZoneObject::new(1, "ZONE-1").unwrap();
        zone.set_occupancy_limits(0, 5).unwrap();
        zone.set_occupancy_count(6);
        db.add(Box::new(zone)).unwrap();
    })
    .await;

    h.request(ADD, alarm_values(zone1(), &[0x91, 4])).await;
    h.settle().await;
    assert_eq!(event_state(&h, zone1()).await, EventState::OFFNORMAL);

    h.request(REMOVE, alarm_values(zone1(), &[0x91, 4])).await;
    h.settle().await;
    assert_eq!(event_state(&h, zone1()).await, EventState::NORMAL);
}

#[tokio::test(start_paused = true)]
async fn alarm_values_list_edit_moves_a_multi_state_input_at_once() {
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        let mut msi = MultiStateInputObject::new(1, "MSI-1", 3).unwrap();
        msi.set_present_value(2);
        db.add(Box::new(msi)).unwrap();
    })
    .await;
    let mut body = BytesMut::new();
    SubscribeCOVRequest {
        subscriber_process_identifier: 889,
        monitored_object_identifier: msi1(),
        issue_confirmed_notifications: Some(false),
        lifetime: Some(300),
    }
    .encode(&mut body)
    .unwrap();
    h.request(ConfirmedServiceChoice::SUBSCRIBE_COV, body).await;
    let initial = h.cov_notification().await;
    assert_eq!(initial.monitored_object_identifier, msi1());

    h.request(ADD, alarm_values(msi1(), &[0x21, 2])).await;
    h.settle().await;
    assert_eq!(event_state(&h, msi1()).await, EventState::OFFNORMAL);
    // The subscriber hears IN_ALARM set.
    let report = h.cov_notification().await;
    let flags = report
        .list_of_values
        .iter()
        .find(|value| value.property_identifier == SF)
        .expect("Status_Flags in the report");
    assert_eq!(flags.value, [0x82, 0x04, 0x80]);
}

#[tokio::test(start_paused = true)]
async fn masked_alarm_values_list_edit_returns_a_door_to_normal_at_once() {
    use bacnet_types::enums::DoorAlarmState;
    let door1 = ObjectIdentifier::new(ObjectType::ACCESS_DOOR, 1).unwrap();
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        // FORCED_OPEN (3) is an alarm value, with Time_Delay 0 (#1149).
        let mut door = AccessDoorObject::new(1, "DOOR-1").unwrap();
        door.set_alarm_values([DoorAlarmState::FORCED_OPEN]).unwrap();
        door.set_door_alarm_state(DoorAlarmState::FORCED_OPEN)
            .unwrap();
        db.add(Box::new(door)).unwrap();
    })
    .await;
    // The application's report reaches the algorithm at the periodic tick.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(event_state(&h, door1).await, EventState::OFFNORMAL);

    // Masking the state the door is in sends it back to NORMAL, and the
    // edit's own evaluation follows it without waiting for a tick.
    h.request(
        ADD,
        list_body(door1, PropertyIdentifier::MASKED_ALARM_VALUES, &[0x91, 3]),
    )
    .await;
    h.settle().await;
    assert_eq!(event_state(&h, door1).await, EventState::NORMAL);
}
