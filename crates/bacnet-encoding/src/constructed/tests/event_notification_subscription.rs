//! Subscribed_Recipients elements (#1049): golden vectors, a list walked one
//! element at a time, and refusal of truncated or malformed elements.

use super::*;
use bacnet_types::constructed::{
    BACnetAddress, BACnetEventNotificationSubscription, BACnetRecipient,
};

/// Device 7, process 7, confirmed, 60 minutes.
const DEVICE_SUBSCRIPTION: &[u8] = &[
    0x0E, 0x0C, 0x02, 0x00, 0x00, 0x07, 0x0F, 0x19, 0x07, 0x29, 0x01, 0x39, 0x3C,
];

/// Network 0x1234 MAC AA:BB, process 9, unconfirmed, 1440 minutes.
const ADDRESS_SUBSCRIPTION: &[u8] = &[
    0x0E, 0x1E, 0x22, 0x12, 0x34, 0x62, 0xAA, 0xBB, 0x1F, 0x0F, 0x19, 0x09, 0x29, 0x00, 0x3A, 0x05,
    0xA0,
];

fn device_subscription() -> BACnetEventNotificationSubscription {
    BACnetEventNotificationSubscription {
        recipient: BACnetRecipient::Device(ObjectIdentifier::new(ObjectType::DEVICE, 7).unwrap()),
        process_identifier: 7,
        issue_confirmed_notifications: true,
        time_remaining: 60,
    }
}

fn address_subscription() -> BACnetEventNotificationSubscription {
    BACnetEventNotificationSubscription {
        recipient: BACnetRecipient::Address(BACnetAddress {
            network_number: 0x1234,
            mac_address: bacnet_types::MacAddr::from_slice(&[0xAA, 0xBB]),
        }),
        process_identifier: 9,
        issue_confirmed_notifications: false,
        time_remaining: 1440,
    }
}

#[test]
fn event_notification_subscription_round_trips_golden_elements() {
    for (bytes, subscription) in [
        (DEVICE_SUBSCRIPTION, device_subscription()),
        (ADDRESS_SUBSCRIPTION, address_subscription()),
    ] {
        let mut buf = BytesMut::new();
        encode_event_notification_subscription(&mut buf, &subscription).unwrap();
        assert_eq!(&buf[..], bytes);
        assert_eq!(
            decode_event_notification_subscription(bytes, 0).unwrap(),
            (subscription, bytes.len())
        );
    }
}

#[test]
fn event_notification_subscription_list_walks_one_element_at_a_time() {
    let mut list = BytesMut::new();
    encode_event_notification_subscription_list(
        &mut list,
        &[address_subscription(), device_subscription()],
    )
    .unwrap();
    assert_eq!(
        &list[..],
        [ADDRESS_SUBSCRIPTION, DEVICE_SUBSCRIPTION].concat()
    );
    let (first, next) = decode_event_notification_subscription(&list, 0).unwrap();
    let (second, end) = decode_event_notification_subscription(&list, next).unwrap();
    assert_eq!(
        (first, next),
        (address_subscription(), ADDRESS_SUBSCRIPTION.len())
    );
    assert_eq!((second, end), (device_subscription(), list.len()));
}

#[test]
fn event_notification_subscription_refuses_truncated_and_malformed_elements() {
    // Every member is required, so no prefix is a whole element.
    for bytes in [DEVICE_SUBSCRIPTION, ADDRESS_SUBSCRIPTION] {
        for len in 0..bytes.len() {
            let result = decode_event_notification_subscription(&bytes[..len], 0);
            assert!(result.is_err(), "prefix {len}: {result:?}");
        }
    }
    // A BOOLEAN contents octet other than 0 or 1.
    let mut flag = DEVICE_SUBSCRIPTION.to_vec();
    assert_eq!(flag[9..11], [0x29, 0x01]);
    flag[10] = 0x02;
    // The recipient CHOICE outside its [0] wrapper.
    let unwrapped = [&DEVICE_SUBSCRIPTION[1..6], &DEVICE_SUBSCRIPTION[7..]].concat();
    // No [2] confirmation flag: [1] is followed by [3].
    let unflagged = [&DEVICE_SUBSCRIPTION[..9], &DEVICE_SUBSCRIPTION[11..]].concat();
    // A process identifier past Unsigned32 (2^32 in five octets).
    let wide_process = [
        &DEVICE_SUBSCRIPTION[..7],
        &[0x1D, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00],
        &DEVICE_SUBSCRIPTION[9..],
    ]
    .concat();
    // A time remaining past Unsigned32.
    let wide_time = [
        &DEVICE_SUBSCRIPTION[..11],
        &[0x3D, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00],
    ]
    .concat();
    // An address MAC of 19 octets, one past BACnetAddress::MAX_MAC_LEN.
    let long_mac = [
        &[0x0E, 0x1E, 0x21, 0x01, 0x65, 0x13][..],
        &[0xAB; 19],
        &[0x1F, 0x0F, 0x19, 0x01, 0x29, 0x00, 0x39, 0x01],
    ]
    .concat();
    for bytes in [
        flag,
        unwrapped,
        unflagged,
        wide_process,
        wide_time,
        long_mac,
    ] {
        let result = decode_event_notification_subscription(&bytes, 0);
        assert!(result.is_err(), "{bytes:02X?}: {result:?}");
    }
}

#[test]
fn event_notification_subscription_takes_the_longest_configured_mac() {
    let subscription = BACnetEventNotificationSubscription {
        recipient: BACnetRecipient::Address(BACnetAddress {
            network_number: 1,
            mac_address: bacnet_types::MacAddr::from_slice(&[0xAB; BACnetAddress::MAX_MAC_LEN]),
        }),
        process_identifier: 1,
        issue_confirmed_notifications: false,
        time_remaining: 1,
    };
    let mut buf = BytesMut::new();
    encode_event_notification_subscription(&mut buf, &subscription).unwrap();
    assert_eq!(
        decode_event_notification_subscription(&buf, 0).unwrap(),
        (subscription, buf.len())
    );
}

#[test]
fn members_cut_short_are_a_short_buffer() {
    let mut framed = 0;
    for wire in [DEVICE_SUBSCRIPTION, ADDRESS_SUBSCRIPTION] {
        framed +=
            super::assert_members_cut_short("BACnetEventNotificationSubscription", wire, |data| {
                decode_event_notification_subscription(data, 0)
            });
    }
    assert!(framed > 0);
}
