//! Inbound WriteGroup on a running server (#1151, Clause 15.11).
//!
//! Every Channel has one member, an Analog Output's Present_Value:
//!
//! | Channel | Channel_Number | Control_Groups | Member, delay           |
//! |---------|----------------|----------------|-------------------------|
//! | CH-1    | 11             | 27             | AO-1, none              |
//! | CH-2    | 11             | 14             | AO-2, none              |
//! | CH-3    | 12             | 5, 27          | AO-3, none              |
//! | CH-4    | 13             | 27             | AO-4, 500 ms, may skip  |
//! | CH-5    | 13             | 0, 27          | AO-5, 500 ms            |
//!
//! "May skip" is Allow_Group_Delay_Inhibit TRUE. Requests arrive as local
//! broadcasts from the harness peer, and everything is read from the
//! database, so any frame the server sends would be an answer. The clock is
//! paused: delays pass only when a test sleeps through them.
use super::*;
use crate::mutation::MutationPolicy;
use crate::server::channel_wire_tests::{ch, channel, member, slot};
use crate::server::command_action_wire_tests::ao;
use crate::server::cov_wire_test_support::{Harness, PEER, PV};
use bacnet_encoding::apdu::encode_apdu;
use bacnet_encoding::npdu::{encode_npdu, Npdu};
use bacnet_objects::analog::AnalogOutputObject;
use bacnet_services::write_group::GroupChannelValue;
use bacnet_transport::port::{ReceivedNpdu, TransportProvenance};
use bacnet_types::enums::WriteStatus;
use std::num::NonZeroU32;

fn objects(db: &mut ObjectDatabase) {
    for instance in 1..=5 {
        db.add(Box::new(
            AnalogOutputObject::new(instance, format!("AO-{instance}"), 62).unwrap(),
        ))
        .unwrap();
    }
    let channels: [(u32, u16, &[u32], u32, bool); 5] = [
        (1, 11, &[27], 0, false),
        (2, 11, &[14], 0, false),
        (3, 12, &[5, 27], 0, false),
        (4, 13, &[27], 500, true),
        (5, 13, &[0, 27], 500, false),
    ];
    for (instance, number, groups, delay, may_skip) in channels {
        let mut object = channel(instance, number, vec![(member(ao(instance), PV), delay)]);
        object.set_control_groups(groups.to_vec()).unwrap();
        object.set_allow_group_delay_inhibit(may_skip);
        db.add(Box::new(object)).unwrap();
    }
}

async fn start(config: ServerConfig) -> Harness {
    Harness::start_with(config, objects).await
}

fn encoded(value: PropertyValue) -> Vec<u8> {
    let mut bytes = BytesMut::new();
    encode_property_value(&mut bytes, &value).unwrap();
    bytes.to_vec()
}

fn real(value: f32) -> Vec<u8> {
    encoded(PropertyValue::Real(value))
}

fn entry(channel: u16, override_priority: Option<u8>, value: Vec<u8>) -> GroupChannelValue {
    GroupChannelValue {
        channel,
        override_priority,
        value,
    }
}

fn request(group: u32, priority: u8, change_list: Vec<GroupChannelValue>) -> WriteGroupRequest {
    WriteGroupRequest {
        group_number: NonZeroU32::new(group).unwrap(),
        write_priority: priority,
        change_list,
        inhibit_delay: None,
    }
}

fn service(request: &WriteGroupRequest) -> Vec<u8> {
    let mut service = BytesMut::new();
    request.encode(&mut service).unwrap();
    service.to_vec()
}

/// Hand the server one WriteGroup carrying `service` as a local broadcast,
/// then let it run what is ready.
async fn send_raw(h: &Harness, service: &[u8]) {
    let mut apdu = BytesMut::new();
    encode_apdu(
        &mut apdu,
        &Apdu::UnconfirmedRequest(UnconfirmedRequestPdu {
            service_choice: UnconfirmedServiceChoice::WRITE_GROUP,
            service_request: Bytes::copy_from_slice(service),
        }),
    )
    .unwrap();
    let mut npdu = BytesMut::new();
    encode_npdu(
        &mut npdu,
        &Npdu {
            payload: apdu.freeze(),
            ..Npdu::default()
        },
    )
    .unwrap();
    h.tx.send(ReceivedNpdu {
        direct_response: None,
        npdu: npdu.freeze(),
        source_mac: MacAddr::from_slice(&PEER),
        link_layer_group: true,
        data_attributes: Vec::new(),
        provenance: TransportProvenance::unverified(),
        reply_tx: None,
    })
    .await
    .unwrap();
    h.settle().await;
}

async fn send(h: &Harness, request: &WriteGroupRequest) {
    send_raw(h, &service(request)).await;
}

async fn read(h: &Harness, instance: u32, property: PropertyIdentifier) -> PropertyValue {
    h.server
        .database()
        .read()
        .await
        .get(&ch(instance))
        .unwrap()
        .read_property(property, None)
        .unwrap()
}

async fn present_value(h: &Harness, instance: u32) -> PropertyValue {
    read(h, instance, PV).await
}

async fn status(h: &Harness, instance: u32) -> WriteStatus {
    match read(h, instance, PropertyIdentifier::WRITE_STATUS).await {
        PropertyValue::Enumerated(raw) => WriteStatus::from_raw(raw),
        other => panic!("Write_Status read {other:?}"),
    }
}

/// Nothing went back on the link: WriteGroup is unconfirmed.
fn assert_silent(h: &Harness) {
    let frames = h.frames.lock().unwrap();
    assert!(frames.is_empty(), "WriteGroup was answered: {frames:?}");
}

/// No Channel took a value and no member was written.
async fn assert_untouched(h: &Harness) {
    for instance in 1..=5 {
        assert_eq!(present_value(h, instance).await, PropertyValue::Null);
        assert_eq!(status(h, instance).await, WriteStatus::IDLE);
        for priority in [8, 16] {
            assert_eq!(slot(h, ao(instance), priority).await, PropertyValue::Null);
        }
    }
}

#[test]
fn write_group_plan_matches_group_and_number_per_channel_in_instance_order() {
    let mut db = ObjectDatabase::new();
    objects(&mut db);
    let planned = |request: &WriteGroupRequest| -> Vec<(u32, u16, u8, Vec<u8>)> {
        plan(&db, request)
            .into_iter()
            .map(|write| {
                let instance = write.channel.instance_number();
                (instance, write.number, write.priority, write.value.to_vec())
            })
            .collect()
    };
    // CH-2 shares channel 11 but not the group.
    assert_eq!(
        planned(&request(
            27,
            8,
            vec![
                entry(13, Some(3), real(1.0)),
                entry(11, None, real(2.0)),
                entry(11, None, real(3.0)),
                entry(12, None, real(4.0)),
            ],
        )),
        [
            (4, 13, 3, real(1.0)),
            (5, 13, 3, real(1.0)),
            (1, 11, 8, real(2.0)),
            (1, 11, 8, real(3.0)),
            (3, 12, 8, real(4.0)),
        ]
    );
    assert_eq!(
        planned(&request(14, 16, vec![entry(11, None, real(5.0))])),
        [(2, 11, 16, real(5.0))]
    );
    // No Channel lists group 6, and group 5 has no channel 11.
    assert!(planned(&request(6, 8, vec![entry(11, None, real(5.0))])).is_empty());
    assert!(planned(&request(5, 8, vec![entry(11, None, real(5.0))])).is_empty());
}

#[tokio::test(start_paused = true)]
async fn write_group_writes_the_channels_in_the_group_with_each_number_at_the_entry_priority() {
    let h = start(ServerConfig::default()).await;
    send(
        &h,
        &request(
            27,
            8,
            vec![
                entry(11, None, real(5.0)),
                entry(12, Some(10), encoded(PropertyValue::Unsigned(7))),
                entry(99, None, real(1.0)),
            ],
        ),
    )
    .await;
    // CH-1: group 27, channel 11, the request's priority, passed on to AO-1.
    assert_eq!(present_value(&h, 1).await, PropertyValue::Real(5.0));
    assert_eq!(
        read(&h, 1, PropertyIdentifier::LAST_PRIORITY).await,
        PropertyValue::Unsigned(8)
    );
    assert_eq!(status(&h, 1).await, WriteStatus::SUCCESSFUL);
    assert_eq!(slot(&h, ao(1), 8).await, PropertyValue::Real(5.0));
    // CH-3: group 27 among others, channel 12, the entry's own priority, the
    // Unsigned coerced to AO-3's REAL (Table 12-63).
    assert_eq!(present_value(&h, 3).await, PropertyValue::Unsigned(7));
    assert_eq!(
        read(&h, 3, PropertyIdentifier::LAST_PRIORITY).await,
        PropertyValue::Unsigned(10)
    );
    assert_eq!(status(&h, 3).await, WriteStatus::SUCCESSFUL);
    assert_eq!(slot(&h, ao(3), 10).await, PropertyValue::Real(7.0));
    assert_eq!(slot(&h, ao(3), 8).await, PropertyValue::Null);
    // CH-2 has channel 11 but is in group 14 only; no Channel has channel 99.
    assert_eq!(present_value(&h, 2).await, PropertyValue::Null);
    assert_eq!(slot(&h, ao(2), 8).await, PropertyValue::Null);
    for instance in [2, 4, 5] {
        assert_eq!(status(&h, instance).await, WriteStatus::IDLE);
    }

    // A NULL relinquishes, as it does through WriteProperty.
    send(&h, &request(27, 8, vec![entry(11, None, vec![0x00])])).await;
    assert_eq!(present_value(&h, 1).await, PropertyValue::Null);
    assert_eq!(slot(&h, ao(1), 8).await, PropertyValue::Null);
    // Group 14 reaches CH-2 and not CH-1, which shares its channel number.
    send(&h, &request(14, 9, vec![entry(11, None, real(2.0))])).await;
    assert_eq!(slot(&h, ao(2), 9).await, PropertyValue::Real(2.0));
    assert_eq!(slot(&h, ao(1), 9).await, PropertyValue::Null);
    assert_silent(&h);
}

#[tokio::test(start_paused = true)]
async fn write_group_inhibit_delay_skips_delays_only_where_the_channel_allows_it() {
    let h = start(ServerConfig::default()).await;
    let mut inhibited = request(27, 8, vec![entry(13, None, real(3.0))]);
    inhibited.inhibit_delay = Some(true);
    send(&h, &inhibited).await;
    // CH-4 allows it, so AO-4 is written at once; CH-5 doesn't, so AO-5
    // waits its 500 ms.
    assert_eq!(slot(&h, ao(4), 8).await, PropertyValue::Real(3.0));
    assert_eq!(status(&h, 4).await, WriteStatus::SUCCESSFUL);
    assert_eq!(slot(&h, ao(5), 8).await, PropertyValue::Null);
    assert_eq!(status(&h, 5).await, WriteStatus::IN_PROGRESS);

    // Without the flag CH-4 keeps its delay too. CH-5 is still busy, so it
    // refuses the new value, and the rest of the list still goes.
    send(
        &h,
        &request(
            27,
            8,
            vec![entry(13, None, real(9.0)), entry(11, None, real(6.0))],
        ),
    )
    .await;
    assert_eq!(present_value(&h, 4).await, PropertyValue::Real(9.0));
    assert_eq!(slot(&h, ao(4), 8).await, PropertyValue::Real(3.0));
    assert_eq!(present_value(&h, 5).await, PropertyValue::Real(3.0));
    assert_eq!(slot(&h, ao(1), 8).await, PropertyValue::Real(6.0));

    tokio::time::sleep(Duration::from_millis(500)).await;
    h.settle().await;
    assert_eq!(status(&h, 4).await, WriteStatus::SUCCESSFUL);
    assert_eq!(status(&h, 5).await, WriteStatus::SUCCESSFUL);
    assert_eq!(slot(&h, ao(4), 8).await, PropertyValue::Real(9.0));
    assert_eq!(slot(&h, ao(5), 8).await, PropertyValue::Real(3.0));
    assert_silent(&h);
}

#[tokio::test(start_paused = true)]
async fn write_group_is_dropped_under_dcc_disable_and_runs_under_disable_initiation() {
    let h = start(ServerConfig::default()).await;
    let write = request(27, 8, vec![entry(11, None, real(5.0))]);
    h.server.comm_state.store(1, Ordering::Release);
    send(&h, &write).await;
    assert_untouched(&h).await;
    // DISABLE_INITIATION stops what the device starts, not what it executes.
    h.server.comm_state.store(2, Ordering::Release);
    send(&h, &write).await;
    assert_eq!(present_value(&h, 1).await, PropertyValue::Real(5.0));
    assert_eq!(slot(&h, ao(1), 8).await, PropertyValue::Real(5.0));
    assert_silent(&h);
}

#[tokio::test(start_paused = true)]
async fn write_group_is_dropped_when_local_policy_restricts_network_writes() {
    let configs = [
        ServerConfig {
            mutation_policy: MutationPolicy::DenyAll,
            ..ServerConfig::default()
        },
        ServerConfig {
            mutation_authorizer: Some(Arc::new(|_| true)),
            ..ServerConfig::default()
        },
    ];
    for config in configs {
        let h = start(config).await;
        send(&h, &request(27, 8, vec![entry(11, None, real(5.0))])).await;
        assert_untouched(&h).await;
        assert_silent(&h);
    }
}

#[tokio::test(start_paused = true)]
async fn write_group_malformed_requests_are_dropped_without_an_answer() {
    let h = start(ServerConfig::default()).await;
    let good = service(&request(27, 8, vec![entry(11, None, real(5.0))]));
    let mut trailing = good.clone();
    trailing.push(0x00);
    // Group 0 is reserved: `09 1B` with its content octet cleared.
    let mut group_zero = good.clone();
    assert_eq!(group_zero[..2], [0x09, 27]);
    group_zero[1] = 0;
    let truncated = good[..good.len() - 1].to_vec();
    for bad in [trailing, group_zero, truncated, Vec::new()] {
        send_raw(&h, &bad).await;
    }
    assert_untouched(&h).await;
    send_raw(&h, &good).await;
    assert_eq!(slot(&h, ao(1), 8).await, PropertyValue::Real(5.0));
    assert_silent(&h);
}

/// Plan `request` on the server's database, let `change` edit that database,
/// then make the planned writes, as when a write lands between the plan and
/// a Channel's own write guard.
async fn plan_change_apply(
    h: &Harness,
    request: &WriteGroupRequest,
    change: impl FnOnce(&mut ObjectDatabase),
) {
    let writes = plan(&*h.server.database().read().await, request);
    assert!(!writes.is_empty(), "nothing planned");
    change(&mut *h.server.database().write().await);
    apply(&CommandRunner::for_server(&h.server), request, &writes).await;
    h.settle().await;
}

fn write_channel_property(
    db: &mut ObjectDatabase,
    instance: u32,
    property: PropertyIdentifier,
    value: PropertyValue,
) {
    db.get_mut(&ch(instance))
        .unwrap()
        .write_property(property, None, value, None)
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn write_group_skips_a_channel_that_left_the_group_after_the_plan() {
    let h = start(ServerConfig::default()).await;
    let write = request(
        27,
        8,
        vec![entry(11, None, real(5.0)), entry(12, None, real(6.0))],
    );
    // The plan picks CH-1 (channel 11) and CH-3 (channel 12). Before their
    // writes CH-1 moves to group 14 and CH-3 to channel 13.
    plan_change_apply(&h, &write, |db| {
        let groups = PropertyValue::List(vec![PropertyValue::Unsigned(14)]);
        write_channel_property(db, 1, PropertyIdentifier::CONTROL_GROUPS, groups);
        let number = PropertyValue::Unsigned(13);
        write_channel_property(db, 3, PropertyIdentifier::CHANNEL_NUMBER, number);
    })
    .await;
    assert_untouched(&h).await;
    assert_silent(&h);
}

#[tokio::test(start_paused = true)]
async fn write_group_reads_allow_group_delay_inhibit_at_the_write() {
    let h = start(ServerConfig::default()).await;
    let mut inhibited = request(27, 8, vec![entry(13, None, real(3.0))]);
    inhibited.inhibit_delay = Some(true);
    // CH-4 allowed the inhibit when planned and stops before its write, so
    // AO-4 waits its 500 ms.
    plan_change_apply(&h, &inhibited, |db| {
        let allow = PropertyValue::Boolean(false);
        write_channel_property(db, 4, PropertyIdentifier::ALLOW_GROUP_DELAY_INHIBIT, allow);
    })
    .await;
    assert_eq!(present_value(&h, 4).await, PropertyValue::Real(3.0));
    assert_eq!(slot(&h, ao(4), 8).await, PropertyValue::Null);
    assert_eq!(status(&h, 4).await, WriteStatus::IN_PROGRESS);
    tokio::time::sleep(Duration::from_millis(500)).await;
    h.settle().await;
    assert_eq!(slot(&h, ao(4), 8).await, PropertyValue::Real(3.0));
    assert_eq!(status(&h, 4).await, WriteStatus::SUCCESSFUL);
    assert_silent(&h);
}
