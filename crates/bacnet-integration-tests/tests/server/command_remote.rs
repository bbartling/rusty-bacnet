use super::*;
use bacnet_objects::analog::AnalogOutputObject;
use bacnet_objects::command::CommandObject;
use bacnet_server::server::DeviceBinding;
use bacnet_types::constructed::{BACnetActionCommand, BACnetActionList};
use bacnet_types::primitives::PropertyValue;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Command actions naming another device (#1180, Clause 12.10.8)
//
// Two servers on loopback B/IP. Device 10 holds CMD-1 and reaches Device 20
// through a configured binding. Device 20 holds AO-1, whose Present_Value
// takes a priority write, and AI-1, whose Present_Value refuses a write while
// it is in service.
// ---------------------------------------------------------------------------

fn oid(object_type: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(object_type, instance).unwrap()
}

fn device(instance: u32) -> DeviceObject {
    DeviceObject::new(DeviceConfig {
        instance,
        name: format!("Device {instance}"),
        ..DeviceConfig::default()
    })
    .unwrap()
}

/// A command for Device 20's `object` Present_Value.
fn remote(object: ObjectIdentifier, value: f32, quit_on_failure: bool) -> BACnetActionCommand {
    BACnetActionCommand {
        device_identifier: Some(oid(ObjectType::DEVICE, 20)),
        object_identifier: object,
        property_identifier: PropertyIdentifier::PRESENT_VALUE,
        property_array_index: None,
        property_value: PropertyValue::Real(value),
        priority: Some(8),
        post_delay: None,
        quit_on_failure,
        write_successful: true,
    }
}

async fn start(db: ObjectDatabase, binding: Option<DeviceBinding>) -> BACnetServer<BipTransport> {
    let mut builder = BACnetServer::bip_builder()
        .interface(Ipv4Addr::LOCALHOST)
        .port(0)
        .broadcast_address(Ipv4Addr::LOCALHOST)
        .database(db);
    if let Some(binding) = binding {
        builder = builder.device_binding(binding).unwrap();
    }
    builder.build().await.unwrap()
}

async fn read(
    db: &Arc<RwLock<ObjectDatabase>>,
    object: ObjectIdentifier,
    property: PropertyIdentifier,
    index: Option<u32>,
) -> PropertyValue {
    db.read()
        .await
        .get(&object)
        .unwrap()
        .read_property(property, index)
        .unwrap()
}

/// Write `list` to CMD-1's Present_Value, wait for the run to end, and return
/// All_Writes_Successful and each command's write-successful flag.
async fn run(server: &BACnetServer<BipTransport>, list: u64) -> (bool, Vec<bool>) {
    let cmd = oid(ObjectType::COMMAND, 1);
    server
        .write_local(
            &cmd,
            PropertyIdentifier::PRESENT_VALUE,
            None,
            PropertyValue::Unsigned(list),
            None,
            bacnet_server::LocalCommandSource::ServerDevice,
        )
        .await
        .unwrap();
    let db = server.database();
    tokio::time::timeout(Duration::from_secs(10), async {
        while read(db, cmd, PropertyIdentifier::IN_PROCESS, None).await
            != PropertyValue::Boolean(false)
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the run ended with In_Process FALSE");
    let all = read(db, cmd, PropertyIdentifier::ALL_WRITES_SUCCESSFUL, None).await;
    let PropertyValue::ApplicationData(element) = read(
        db,
        cmd,
        PropertyIdentifier::ACTION,
        Some(u32::try_from(list).unwrap()),
    )
    .await
    else {
        panic!("an encoded action list");
    };
    let (decoded, _) = bacnet_encoding::constructed::decode_action_list(&element, 0).unwrap();
    let flags = decoded
        .commands
        .iter()
        .map(|command| command.write_successful)
        .collect();
    (all == PropertyValue::Boolean(true), flags)
}

#[tokio::test]
async fn command_writes_a_target_in_another_device_over_bip() {
    let ao = oid(ObjectType::ANALOG_OUTPUT, 1);
    let ai = oid(ObjectType::ANALOG_INPUT, 1);
    let mut target_db = ObjectDatabase::new();
    target_db.add(Box::new(device(20))).unwrap();
    target_db
        .add(Box::new(AnalogOutputObject::new(1, "AO-1", 62).unwrap()))
        .unwrap();
    target_db
        .add(Box::new(AnalogInputObject::new(1, "AI-1", 62).unwrap()))
        .unwrap();
    let mut target = start(target_db, None).await;

    let mut command = CommandObject::new(1, "CMD-1").unwrap();
    command
        .set_action(vec![
            BACnetActionList {
                commands: vec![remote(ao, 42.0, false)],
            },
            // AI-1 refuses; the failure quits before AO-1 is written again.
            BACnetActionList {
                commands: vec![remote(ai, 1.0, true), remote(ao, 7.0, false)],
            },
        ])
        .unwrap();
    let mut commander_db = ObjectDatabase::new();
    commander_db.add(Box::new(device(10))).unwrap();
    commander_db.add(Box::new(command)).unwrap();
    let binding = DeviceBinding::local(oid(ObjectType::DEVICE, 20), target.local_mac()).unwrap();
    let mut commander = start(commander_db, Some(binding)).await;

    assert_eq!(run(&commander, 1).await, (true, vec![true]));
    let slot8 = read(
        target.database(),
        ao,
        PropertyIdentifier::PRIORITY_ARRAY,
        Some(8),
    )
    .await;
    assert_eq!(slot8, PropertyValue::Real(42.0));

    assert_eq!(run(&commander, 2).await, (false, vec![false, false]));
    let slot8 = read(
        target.database(),
        ao,
        PropertyIdentifier::PRIORITY_ARRAY,
        Some(8),
    )
    .await;
    assert_eq!(slot8, PropertyValue::Real(42.0));

    commander.stop().await.unwrap();
    target.stop().await.unwrap();
}
