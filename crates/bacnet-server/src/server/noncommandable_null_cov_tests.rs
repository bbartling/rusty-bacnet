//! A NULL written to a property of AV-1 that isn't commandable and has no
//! NULL in its datatype succeeds and changes nothing (#1396), so a COV
//! subscriber to AV-1 hears nothing of it: over WriteProperty,
//! WritePropertyMultiple or `write_local_encoded`. A real change still
//! reaches the subscriber.
use super::cov_wire_test_support::*;
use super::*;
use bacnet_services::common::BACnetPropertyValue;
use bacnet_services::wpm::{WriteAccessSpecification, WritePropertyMultipleRequest};
use bacnet_services::write_property::WritePropertyRequest;

const NULL: [u8; 1] = [0x00];

async fn write_property(
    h: &mut Harness,
    property: PropertyIdentifier,
    value: Vec<u8>,
) -> Result<(), ErrorCode> {
    let mut body = BytesMut::new();
    WritePropertyRequest {
        object_identifier: av1(),
        property_identifier: property,
        property_array_index: None,
        property_value: value,
        priority: None,
    }
    .encode(&mut body)
    .unwrap();
    h.request(ConfirmedServiceChoice::WRITE_PROPERTY, body)
        .await;
    response(h).await
}

async fn write_property_multiple(
    h: &mut Harness,
    properties: &[PropertyIdentifier],
) -> Result<(), ErrorCode> {
    let mut body = BytesMut::new();
    WritePropertyMultipleRequest {
        list_of_write_access_specs: vec![WriteAccessSpecification {
            object_identifier: av1(),
            list_of_properties: properties
                .iter()
                .map(|&property| BACnetPropertyValue {
                    property_identifier: property,
                    property_array_index: None,
                    value: NULL.to_vec(),
                    priority: None,
                })
                .collect(),
        }],
    }
    .encode(&mut body)
    .unwrap();
    h.request(ConfirmedServiceChoice::WRITE_PROPERTY_MULTIPLE, body)
        .await;
    response(h).await
}

#[tokio::test]
async fn a_null_left_unchanged_sends_no_cov_notification() {
    let mut h = Harness::start(ServerConfig::default()).await;
    h.subscribe_cov().await;
    h.cov_notification().await;

    // COV_Increment is refused as a NULL by AV-1 and left unchanged by the
    // server; Out_Of_Service and Description AV-1 leaves unchanged itself.
    for property in [
        PropertyIdentifier::COV_INCREMENT,
        PropertyIdentifier::OUT_OF_SERVICE,
        PropertyIdentifier::DESCRIPTION,
    ] {
        assert_eq!(
            write_property(&mut h, property, NULL.to_vec()).await,
            Ok(()),
            "{property:?}"
        );
        h.no_notification().await;
    }
    assert_eq!(
        write_property_multiple(
            &mut h,
            &[
                PropertyIdentifier::COV_INCREMENT,
                PropertyIdentifier::OUT_OF_SERVICE,
            ],
        )
        .await,
        Ok(())
    );
    h.no_notification().await;
    h.server
        .write_local_encoded(
            &av1(),
            PropertyIdentifier::COV_INCREMENT,
            None,
            &NULL,
            None,
            crate::LocalCommandSource::ServerDevice,
        )
        .await
        .unwrap();
    h.no_notification().await;

    // A change does reach the subscriber: Status_Flags gains OUT_OF_SERVICE.
    let mut active = BytesMut::new();
    bacnet_encoding::primitives::encode_app_boolean(&mut active, true);
    assert_eq!(
        write_property(&mut h, PropertyIdentifier::OUT_OF_SERVICE, active.to_vec()).await,
        Ok(())
    );
    let notification = h.cov_notification().await;
    assert_eq!(notification.monitored_object_identifier, av1());
}
