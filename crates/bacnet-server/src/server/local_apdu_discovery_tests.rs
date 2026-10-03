//! Direct handler controls await completion; no silence-as-completion assumption.
use super::*;

#[tokio::test]
async fn who_is_rechecks_selected_device_raw_capacity_and_recovers() {
    let (transport, capture, _tx) = discovery_transport();
    let mut db = ObjectDatabase::new();
    let oid = ObjectIdentifier::new(ObjectType::DEVICE, 893).unwrap();
    db.add(Box::new(
        DeviceObject::new(DeviceConfig {
            instance: 893,
            max_apdu_length: 1474,
            ..Default::default()
        })
        .unwrap(),
    ))
    .unwrap();
    let mut server = BACnetServer::start(
        ServerConfig {
            max_apdu_length: 1474,
            ..Default::default()
        },
        db,
        transport,
    )
    .await
    .unwrap();
    for (capacity, expected_sends) in [(Some(1474), 1), (Some(1476), 1), (None, 1), (Some(1474), 2)]
    {
        {
            let mut db = server.db.write().await;
            if db.get(&oid).is_some() {
                db.remove(&oid).unwrap();
            }
            if let Some(max_apdu_length) = capacity {
                db.add(Box::new(
                    DeviceObject::new(DeviceConfig {
                        instance: 893,
                        max_apdu_length,
                        ..Default::default()
                    })
                    .unwrap(),
                ))
                .unwrap();
            }
        }
        BACnetServer::handle_unconfirmed_request(
            &server.test_unconfirmed_services(),
            UnconfirmedRequestPdu {
                service_choice: UnconfirmedServiceChoice::WHO_IS,
                service_request: Bytes::new(),
            },
            &bacnet_network::layer::ReceivedApdu {
                direct_response: None,
                apdu: Bytes::new(),
                source_mac: MacAddr::from_slice(&[2]),
                ingress_network: None,
                source_network: None,
                link_layer_group: false,
                is_group: false,
                global_broadcast: false,
                data_attributes: vec![],
                provenance: TransportProvenance::unverified(),
                reply_tx: None,
            },
        )
        .await;
        assert_eq!(capture.unicasts().len(), expected_sends);
        assert_eq!(server.discovery_counters().i_am_sent, expected_sends as u64);
    }
    for frame in capture.unicasts() {
        let Apdu::UnconfirmedRequest(request) =
            decode_apdu(decode_npdu(frame.npdu).unwrap().payload).unwrap()
        else {
            panic!("I-Am expected")
        };
        assert_eq!(request.service_choice, UnconfirmedServiceChoice::I_AM);
        assert_eq!(
            IAmRequest::decode(&request.service_request)
                .unwrap()
                .max_apdu_length,
            1474
        );
    }
    server.stop().await.unwrap();
}

#[tokio::test]
async fn actual_mstp_default_no_device_start_clamps_to_480_without_iam() {
    use bacnet_transport::mstp::{LoopbackSerial, MstpConfig, MstpTransport};
    let (serial, _peer) = LoopbackSerial::pair();
    let mut server = BACnetServer::start(
        ServerConfig::default(),
        ObjectDatabase::new(),
        MstpTransport::new(serial, MstpConfig::default()),
    )
    .await
    .unwrap();
    assert_eq!(server.config.max_apdu_length, 480);
    assert!(server.broadcast_i_am().await.is_err());
    assert_eq!(server.discovery_counters().i_am_sent, 0);
    server.stop().await.unwrap();
}
