use super::*;
use bacnet_objects::{network_port::NetworkPortObject, traits::BACnetObject};
use bacnet_types::primitives::PropertyValue;
use PropertyIdentifier as P;

#[test]
fn pics_network_port_property_metadata_is_exact() {
    // Independent (identifier, optional, writable) rows in declaration order; PICS sorts by property ID.
    let expected = [
        (P::OBJECT_IDENTIFIER, false, false),
        (P::OBJECT_NAME, false, false),
        (P::DESCRIPTION, true, true),
        (P::OBJECT_TYPE, false, false),
        (P::STATUS_FLAGS, false, false),
        (P::OUT_OF_SERVICE, false, true),
        (P::RELIABILITY, false, false),
        (P::NETWORK_TYPE, false, false),
        (P::PROTOCOL_LEVEL, false, false),
        (P::NETWORK_NUMBER, false, false),
        (P::NETWORK_NUMBER_QUALITY, false, false),
        (P::MAC_ADDRESS, false, false),
        (P::APDU_LENGTH, false, false),
        (P::LINK_SPEED, true, false),
        (P::CHANGES_PENDING, false, false),
        (P::BACNET_IP_MODE, false, false),
        (P::IP_ADDRESS, false, false),
        (P::IP_DEFAULT_GATEWAY, false, false),
        (P::IP_SUBNET_MASK, false, false),
        (P::BACNET_IP_UDP_PORT, false, false),
        (P::IP_DNS_SERVER, false, false),
        (P::PROPERTY_LIST, false, false),
    ];
    for configured in [false, true] {
        for out_of_service in [false, true] {
            let mut object = NetworkPortObject::new_bip(
                7,
                "NP-7",
                bacnet_objects::network_port::BipPortConfig {
                    ip_address: if configured {
                        [192, 168, 1, 100]
                    } else {
                        [0; 4]
                    },
                    udp_port: if configured { 47809 } else { 47808 },
                    network_number: if configured { 5 } else { 0 },
                    ..Default::default()
                },
            )
            .unwrap();
            if configured {
                object.set_description("long network port label".repeat(100));
            }
            object
                .write_property(
                    P::OUT_OF_SERVICE,
                    None,
                    PropertyValue::Boolean(out_of_service),
                    None,
                )
                .unwrap();
            let required = object.required_properties();
            let mut db = ObjectDatabase::new();
            db.add(Box::new(object)).unwrap();
            let pics = generate_pics(&db, &ServerConfig::default(), &PicsConfig::default());
            assert_eq!(pics.supported_object_types.len(), 1);
            let support = &pics.supported_object_types[0];
            assert_eq!(support.object_type, ObjectType::NETWORK_PORT);
            assert!(!support.createable);
            assert!(!support.deleteable);
            let rows: Vec<_> = support
                .supported_properties
                .iter()
                .map(|row| {
                    assert!(row.access.readable);
                    (row.property_id, row.access.optional, row.access.writable)
                })
                .collect();
            assert_eq!(
                rows,
                sorted_rows(&expected),
                "configured={configured}, OOS={out_of_service}"
            );
            assert_eq!(
                rows.iter()
                    .filter_map(|&(p, optional, _)| (!optional).then_some(p))
                    .collect::<Vec<_>>(),
                sorted_required(required.as_ref())
            );
        }
    }
}

#[test]
fn pics_non_bip_application_profiles_exclude_ipv4_rows() {
    let expected = [
        (P::OBJECT_IDENTIFIER, false, false),
        (P::OBJECT_NAME, false, false),
        (P::DESCRIPTION, true, true),
        (P::OBJECT_TYPE, false, false),
        (P::STATUS_FLAGS, false, false),
        (P::OUT_OF_SERVICE, false, true),
        (P::RELIABILITY, false, false),
        (P::NETWORK_TYPE, false, false),
        (P::PROTOCOL_LEVEL, false, false),
        (P::NETWORK_NUMBER, false, false),
        (P::NETWORK_NUMBER_QUALITY, false, false),
        (P::MAC_ADDRESS, false, false),
        (P::APDU_LENGTH, false, false),
        (P::LINK_SPEED, true, false),
        (P::CHANGES_PENDING, false, false),
        (P::PROPERTY_LIST, false, false),
    ];
    for kind in [
        bacnet_types::enums::NetworkType::ETHERNET,
        bacnet_types::enums::NetworkType::VIRTUAL,
    ] {
        let object =
            NetworkPortObject::new_non_bip(0, "non-B/IP", kind, 0, Default::default(), 1476)
                .unwrap();
        let mut db = ObjectDatabase::new();
        db.add(Box::new(object)).unwrap();
        let pics = generate_pics(&db, &ServerConfig::default(), &PicsConfig::default());
        let rows: Vec<_> = pics.supported_object_types[0]
            .supported_properties
            .iter()
            .map(|row| (row.property_id, row.access.optional, row.access.writable))
            .collect();
        assert_eq!(rows, sorted_rows(&expected));
    }
}
