//! A provisioned recipient Address naming the session's network starts
//! unresolved while the session has not learned its number, as a Device
//! with no binding does, and resolves once it has (#1461). It resolves
//! against the number in force at each operation, so a replaced number
//! leaves it unresolved, and a recipient change then goes ahead with no
//! copy for it.
use super::*;
use bacnet_types::enums::{PropertyIdentifier, Reliability};
use bacnet_types::primitives::PropertyValue;

async fn reliability(endpoint: &Endpoint) -> Reliability {
    let db = endpoint.session.database.as_ref().unwrap().read().await;
    let PropertyValue::Enumerated(value) = db
        .get(&oid(ObjectType::AUDIT_REPORTER, 1))
        .unwrap()
        .read_property(PropertyIdentifier::RELIABILITY, None)
        .unwrap()
    else {
        panic!("Reliability is an enumeration")
    };
    Reliability::from_raw(value)
}

fn direct() -> EndpointApduDestination {
    EndpointApduDestination::Direct {
        destination_mac: mac(PEER),
    }
}

/// Complete a direct read that has no recipient to report to. Nothing else
/// may go out before the next frame a test expects: a stray record would
/// stand in its place.
async fn unreported_read(endpoint: &mut Endpoint) {
    let read = endpoint.read(direct());
    let (route, request) = endpoint.request().await;
    assert_eq!(route, local(PEER));
    endpoint
        .deliver_apdu(ack(&request, 5), mac(PEER), None)
        .await;
    bounded(read).await.unwrap().unwrap();
}

#[tokio::test]
async fn an_address_on_the_network_starts_unresolved_and_resolves_once_learned() {
    for role in [SessionRole::ClientOnly, SessionRole::Both] {
        // Before #1461 the session refused to start with this recipient.
        let mut endpoint = source_reporting_to(role, false, address(THIS_NETWORK, SINK)).await;
        assert_eq!(
            reliability(&endpoint).await,
            Reliability::CONFIGURATION_ERROR,
            "{role:?}"
        );
        unreported_read(&mut endpoint).await;
        assert_eq!(
            reliability(&endpoint).await,
            Reliability::CONFIGURATION_ERROR
        );
        // Learning the number is the next exchange, so no record went out.
        endpoint.learn(THIS_NETWORK).await;
        audited_read(&mut endpoint, direct(), SINK).await;
        assert_eq!(reliability(&endpoint).await, Reliability::NO_FAULT_DETECTED);
        endpoint.stop().await;
    }
}

#[tokio::test]
async fn a_replaced_number_unresolves_the_address_and_a_change_still_goes_ahead() {
    for role in [SessionRole::ClientOnly, SessionRole::Both] {
        let mut endpoint = source_reporting_to(role, true, address(THIS_NETWORK, SINK)).await;
        audited_read(&mut endpoint, direct(), SINK).await;
        // A later announcement replaces the learned number.
        endpoint.learn(REMOTE_NETWORK).await;
        unreported_read(&mut endpoint).await;
        assert_eq!(
            reliability(&endpoint).await,
            Reliability::CONFIGURATION_ERROR,
            "{role:?}"
        );
        // The old address has no route now; the change is not refused for
        // it, and only the new recipient gets the change's record.
        let next = address(REMOTE_NETWORK, NEW_SINK);
        bounded(endpoint.session.write_audit_recipient(Some(next)))
            .await
            .unwrap();
        let change = record(endpoint.next().await, NEW_SINK);
        assert_eq!(change.operation, AuditOperation::WRITE);
        let mut old = bytes::BytesMut::new();
        bacnet_encoding::constructed::encode_recipient(&mut old, &address(THIS_NETWORK, SINK))
            .unwrap();
        assert_eq!(change.current_value.as_deref(), Some(&old[..]));
        // The next frame is the read's request: no second copy went out.
        audited_read(&mut endpoint, direct(), NEW_SINK).await;
        assert_eq!(reliability(&endpoint).await, Reliability::NO_FAULT_DETECTED);
        endpoint.stop().await;
    }
}
