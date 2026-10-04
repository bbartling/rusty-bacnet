//! A lighting command written to a Channel reaches a Lighting Output
//! member's Lighting_Command (#1263; Clause 12.53, Table 12-63). The
//! WriteGroup case, in `write_group_tests.rs`, uses these fixtures.
//!
//! CH-1 (channel 11, control group 27) has one member, LO-1's
//! Lighting_Command, with no delay. The clock is paused.
use super::channel_wire_tests::{channel, member, settled, write_channel};
use super::command_action_wire_tests::read_db;
use super::cov_wire_test_support::*;
use super::*;
use bacnet_objects::lighting::LightingOutputObject;
use bacnet_types::enums::WriteStatus;

/// FADE_TO 50.0 % at priority 8, framed in context tag 0 as a channel value
/// carries it.
pub(super) const FRAMED: [u8; 11] = [
    0x0E, 0x09, 0x01, 0x1C, 0x42, 0x48, 0x00, 0x00, 0x59, 0x08, 0x0F,
];

fn lo1() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::LIGHTING_OUTPUT, 1).unwrap()
}

pub(super) fn objects(db: &mut ObjectDatabase) {
    db.add(Box::new(LightingOutputObject::new(1, "LO-1").unwrap()))
        .unwrap();
    let mut object = channel(
        1,
        11,
        vec![(member(lo1(), PropertyIdentifier::LIGHTING_COMMAND), 0)],
    );
    object.set_control_groups(vec![27]).unwrap();
    db.add(Box::new(object)).unwrap();
}

/// LO-1's Lighting_Command as ReadProperty would serve it.
pub(super) async fn lighting_command(h: &Harness) -> Vec<u8> {
    let value = read_db(h, lo1(), PropertyIdentifier::LIGHTING_COMMAND, None).await;
    let mut encoded = BytesMut::new();
    encode_property_value(&mut encoded, &value).unwrap();
    encoded.to_vec()
}

#[tokio::test(start_paused = true)]
async fn channel_lighting_command_reaches_a_lighting_output() {
    let mut h = Harness::start_with(ServerConfig::default(), objects).await;
    write_channel(
        &mut h,
        1,
        &PropertyValue::ApplicationData(FRAMED.to_vec()),
        None,
    )
    .await
    .unwrap();
    assert_eq!(settled(&mut h, 1).await, WriteStatus::SUCCESSFUL);
    // The member holds the SEQUENCE without the channel value's framing.
    assert_eq!(lighting_command(&h).await, FRAMED[1..FRAMED.len() - 1]);
}
