//! A Recipient_List destination whose address MAC is longer than
//! `BACnetAddress::MAX_MAC_LEN` (18 octets, B/IPv6) is refused on the wire
//! (#1124). It does not decode, so WriteProperty answers PROPERTY /
//! INVALID_DATA_TYPE and AddListElement a ChangeList-Error naming the element;
//! the stored list stays as it was.
//!
//! PROPERTY 2; INVALID_DATA_TYPE 9.

use super::mutation_list_wire_tests::{change_list_error, list_request, wire, ADD};
use super::mutation_tests::{oid, Fixture};
use super::*;
use bacnet_encoding::constructed::encode_destination_list;
use bacnet_objects::notification_class::NotificationClass;
use bacnet_services::write_property::WritePropertyRequest;
use bacnet_types::bitstring::{DaysOfWeek, EventTransitionBits};
use bacnet_types::constructed::{BACnetAddress, BACnetDestination, BACnetRecipient};
use bacnet_types::primitives::Time;

const RECIPIENT_LIST: PropertyIdentifier = PropertyIdentifier::RECIPIENT_LIST;

/// A destination for every day, time and transition. `mac` of `None` names
/// Device 9; `Some(len)` an address on network 1000 with a `len`-octet MAC.
fn destination(mac: Option<usize>) -> BACnetDestination {
    let time = |hour, minute| Time {
        hour,
        minute,
        second: 0,
        hundredths: 0,
    };
    BACnetDestination {
        valid_days: DaysOfWeek::all(),
        from_time: time(0, 0),
        to_time: time(23, 59),
        recipient: match mac {
            None => BACnetRecipient::Device(oid(ObjectType::DEVICE, 9)),
            Some(len) => BACnetRecipient::Address(BACnetAddress {
                network_number: 1000,
                mac_address: MacAddr::from_slice(&vec![0xA5; len]),
            }),
        },
        process_identifier: 1,
        issue_confirmed_notifications: false,
        transitions: EventTransitionBits::all(),
    }
}

fn framed(destinations: &[BACnetDestination]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    encode_destination_list(&mut buf, destinations);
    buf.to_vec()
}

/// A fixture holding Notification Class 1 with one device destination.
async fn fixture() -> (Fixture, ObjectIdentifier) {
    let fixture = Fixture::new(None);
    let mut class = NotificationClass::new(1, "NC-1").unwrap();
    class.add_destination(destination(None)).unwrap();
    fixture.db.write().await.add(Box::new(class)).unwrap();
    (fixture, oid(ObjectType::NOTIFICATION_CLASS, 1))
}

fn write_property(class: ObjectIdentifier, destinations: &[BACnetDestination]) -> Bytes {
    let mut request = BytesMut::new();
    WritePropertyRequest {
        object_identifier: class,
        property_identifier: RECIPIENT_LIST,
        property_array_index: None,
        property_value: framed(destinations),
        priority: None,
    }
    .encode(&mut request)
    .unwrap();
    request.freeze()
}

#[tokio::test]
async fn write_property_of_a_recipient_mac_past_the_bound_is_invalid_data_type() {
    let (fixture, class) = fixture().await;
    let service = ConfirmedServiceChoice::WRITE_PROPERTY;
    let before = fixture.read(class, RECIPIENT_LIST).await;
    let longest = destination(Some(BACnetAddress::MAX_MAC_LEN));
    for len in [BACnetAddress::MAX_MAC_LEN + 1, 255] {
        assert_eq!(
            wire(
                &fixture,
                service,
                write_property(class, &[longest.clone(), destination(Some(len))])
            )
            .await,
            vec![0x50, 5, service.to_raw(), 0x91, 2, 0x91, 9],
            "{len}-octet MAC"
        );
        assert_eq!(fixture.read(class, RECIPIENT_LIST).await, before, "{len}");
    }
    // The longest MAC this stack uses is still a destination.
    assert_eq!(
        wire(
            &fixture,
            service,
            write_property(class, std::slice::from_ref(&longest))
        )
        .await,
        vec![0x20, 5, service.to_raw()]
    );
    assert_eq!(
        fixture.read(class, RECIPIENT_LIST).await,
        PropertyValue::ApplicationData(framed(&[longest]))
    );
}

#[tokio::test]
async fn add_list_element_names_the_recipient_mac_past_the_bound() {
    let (fixture, class) = fixture().await;
    let before = fixture.read(class, RECIPIENT_LIST).await;
    let elements = framed(&[
        destination(Some(BACnetAddress::MAX_MAC_LEN)),
        destination(Some(BACnetAddress::MAX_MAC_LEN + 1)),
    ]);
    assert_eq!(
        wire(
            &fixture,
            ADD,
            list_request(class, RECIPIENT_LIST, None, &elements)
        )
        .await,
        change_list_error(ADD, 2, 9, 2)
    );
    assert_eq!(fixture.read(class, RECIPIENT_LIST).await, before);
}
