//! How the forwarding cap counts (#1259): only copies that would be sent
//! take room, a local notification that names this device's Device object
//! under several process identifiers has one cap, and the cap warning is
//! throttled.

use super::event_forwarding::{Reception, WarnThrottle, CAP_WARNING_INTERVAL};
use super::event_forwarding_bounds_tests::peer;
use super::event_forwarding_tests::{
    database, destination, notification, unconfirmed, Forwarding, To, LOCAL_DEVICE,
};
use super::event_recipient_routing_tests::{address_recipient, distribute_counted};
use super::*;
use bacnet_objects::notification_class::NotificationClass;
use bacnet_objects::notification_forwarder::NotificationForwarderObject;
use bacnet_types::constructed::BACnetRecipient;

/// A node on network 5, one per `index`.
fn remote(index: usize) -> [u8; 2] {
    [0x0E, index as u8]
}

#[tokio::test]
async fn the_cap_counts_only_copies_the_loop_rules_let_through() {
    // The notification arrives by broadcast. Forwarder 1 names 30 nodes on
    // this network, which the loop rules refuse; forwarders 2 to 4 name 70
    // nodes on network 5 (indices 30 to 99).
    let forwarders = (0..4u32)
        .map(|n| {
            let mut nf = NotificationForwarderObject::new(n + 1, format!("NF-{n}")).unwrap();
            let count = if n == 3 { 10 } else { 30 };
            for offset in 0..count {
                let index = n as usize * 30 + offset;
                let recipient = if n == 0 {
                    address_recipient(0, &peer(index))
                } else {
                    address_recipient(5, &remote(index))
                };
                nf.add_destination(destination(recipient, index as u32, false))
                    .unwrap();
            }
            nf
        })
        .collect();
    let forwarding = Forwarding::new(database(forwarders));
    let broadcast = Reception {
        group: true,
        global: false,
    };
    // The refused nodes take no room: the first 64 of the 70 remote nodes go.
    let expected: Vec<_> = (30..30 + MAX_FORWARDED_DESTINATIONS)
        .map(|index| unconfirmed(To::Remote(5, remote(index).to_vec()), index as u32))
        .collect();
    assert_eq!(
        forwarding.receive(&notification(5), broadcast).await,
        expected
    );
    assert_eq!(
        forwarding.counters(),
        EventNotificationCounters {
            forwarding_cap_dropped: (70 - MAX_FORWARDED_DESTINATIONS) as u64,
            ..Default::default()
        }
    );
}

#[tokio::test]
async fn a_local_notification_under_several_process_identifiers_has_one_cap() {
    let this_device =
        BACnetRecipient::Device(ObjectIdentifier::new(ObjectType::DEVICE, LOCAL_DEVICE).unwrap());
    // Notification Class 0 names this device under processes 5 and 6.
    let mut class = NotificationClass::new(0, "NC-0").unwrap();
    for process in [5, 6] {
        class
            .add_destination(destination(this_device.clone(), process, false))
            .unwrap();
    }
    let node = |index: usize| destination(address_recipient(0, &peer(index)), index as u32, false);
    // Forwarder 1 takes process 5 with nodes 0 to 31. Forwarders 2 and 3
    // take process 6: forwarder 2 with node 0 again and nodes 32 to 62,
    // forwarder 3 with nodes 63 to 72. That is 73 distinct destinations.
    let mut db = ObjectDatabase::new();
    db.add(Box::new(class)).unwrap();
    for (instance, process, nodes) in [
        (1, 5, (0..32).collect::<Vec<_>>()),
        (2, 6, std::iter::once(0).chain(32..63).collect()),
        (3, 6, (63..73).collect()),
    ] {
        let mut nf = NotificationForwarderObject::new(instance, format!("NF-{instance}")).unwrap();
        nf.set_process_identifier_filter(Some(process));
        for index in nodes {
            nf.add_destination(node(index)).unwrap();
        }
        db.add(Box::new(nf)).unwrap();
    }

    let (broadcasts, unicasts, counters) = distribute_counted(
        db,
        Arc::new(RwLock::new(
            super::device_bindings::DeviceBindingTable::new(),
        )),
        0,
    )
    .await;
    assert!(broadcasts.is_empty());
    // Node 0 gets one copy, and the 73 destinations share one cap of 64.
    let reached: Vec<Vec<u8>> = unicasts.into_iter().map(|(mac, _)| mac).collect();
    let expected: Vec<Vec<u8>> = (0..MAX_FORWARDED_DESTINATIONS)
        .map(|index| peer(index).to_vec())
        .collect();
    assert_eq!(reached, expected);
    assert_eq!(
        counters,
        EventNotificationCounters {
            forwarding_cap_dropped: (73 - MAX_FORWARDED_DESTINATIONS) as u64,
            ..Default::default()
        }
    );
}

#[test]
fn the_cap_warning_goes_out_at_most_once_an_interval() {
    let throttle = WarnThrottle::new();
    let start = std::time::Instant::now();
    assert!(throttle.due(start));
    assert!(!throttle.due(start + CAP_WARNING_INTERVAL - Duration::from_millis(1)));
    assert!(throttle.due(start + CAP_WARNING_INTERVAL));
    assert!(!throttle.due(start + CAP_WARNING_INTERVAL + Duration::from_secs(1)));
}
