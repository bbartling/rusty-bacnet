use super::*;
use crate::cov::{CovObservation, CovSample, SubscriberEndpoint};

fn routed(confirmed: bool) -> CovSubscription {
    let mut sub = proposal(
        CovNotificationKind::Multiple,
        confirmed,
        PropertyIdentifier::PRESENT_VALUE,
    );
    sub.subscriber_network = Some(bacnet_encoding::npdu::NpduAddress {
        network: 7,
        mac_address: MacAddr::from_slice(&[4]),
    });
    sub
}

async fn migrate(fixture: &Fixture, old: &CovSubscriptionSnapshot) -> CovSubscriptionSnapshot {
    let route =
        SubscriberEndpoint::new(&[127, 0, 0, 9, 0xba, 0xd0], old.subscriber_network.as_ref());
    let mut table = fixture.table.write().await;
    table
        .subscribe_multiple(
            old.key().multiple_context().unwrap(),
            &route,
            Instant::now() + Duration::from_secs(600),
            1,
            vec![],
        )
        .unwrap();
    assert!(!table.is_current(old));
    table.get_subscription(old.key()).unwrap().clone()
}

fn observation(value: f32) -> CovObservation {
    CovObservation::new(CovSample::new(&PropertyValue::Real(value)).unwrap(), None).unwrap()
}

#[tokio::test]
async fn cov_multiple_route_held_unconfirmed_completion_cannot_advance_migrated_baseline() {
    for initial in [true, false] {
        let fixture = Fixture::new(true);
        let old = fixture
            .table
            .write()
            .await
            .admit_for_test(routed(false), 0)
            .unwrap();
        let snapshots = [old.clone()];
        let mut work = Box::pin(fixture.fire(initial, &snapshots));
        assert!(futures_util::poll!(work.as_mut()).is_pending());
        assert_eq!(
            fixture.routes.lock().unwrap().as_slice(),
            std::slice::from_ref(&old.subscriber_mac)
        );
        let current = migrate(&fixture, &old).await;
        fixture.release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(2), work)
            .await
            .unwrap();
        assert_eq!(
            fixture
                .table
                .read()
                .await
                .get_subscription(old.key())
                .unwrap()
                .last_notified_observation,
            Some(observation(1.0)),
            "old-route success cannot advance the new route's baseline"
        );
        // The next real notification uses the new immediate router and the same
        // remote BACnet destination; no competing old-route owner survives.
        fixture.release.add_permits(1);
        fixture.fire(initial, std::slice::from_ref(&current)).await;
        assert_eq!(
            fixture.routes.lock().unwrap().as_slice(),
            &[old.subscriber_mac.clone(), current.subscriber_mac.clone()]
        );
        let frame = fixture.sent.lock().unwrap()[1].clone();
        assert_eq!(
            decode_npdu(frame).unwrap().destination,
            old.subscriber_network
        );
        assert_eq!(
            fixture
                .table
                .read()
                .await
                .get_subscription(old.key())
                .unwrap()
                .last_notified_observation
                .as_ref()
                .unwrap()
                .sample(),
            &CovSample::new(&PropertyValue::Real(10.0)).unwrap()
        );
        fixture.finish(false).await;
    }
}

#[tokio::test]
async fn cov_multiple_route_migration_before_admission_suppresses_captured_initials() {
    for confirmed in [false, true] {
        let fixture = Fixture::new(false);
        let old = fixture
            .table
            .write()
            .await
            .admit_for_test(routed(confirmed), 0)
            .unwrap();
        let snapshots = [old.clone()];
        let guard = fixture.db.write().await;
        let mut work = Box::pin(fixture.fire(true, &snapshots));
        assert!(futures_util::poll!(work.as_mut()).is_pending());
        migrate(&fixture, &old).await;
        drop(guard);
        tokio::time::timeout(Duration::from_secs(2), work)
            .await
            .unwrap();
        assert!(fixture.sent.lock().unwrap().is_empty());
        assert_eq!(fixture.transactions.active_count(), 0);
        assert_eq!(
            fixture
                .table
                .read()
                .await
                .get_subscription(old.key())
                .unwrap()
                .last_notified_observation,
            Some(observation(1.0))
        );
        fixture.finish(false).await;
    }
}

#[tokio::test]
async fn cov_multiple_route_admitted_confirmed_worker_may_finish_on_old_route() {
    let fixture = Fixture::new(true);
    let old = fixture
        .table
        .write()
        .await
        .admit_for_test(routed(true), 0)
        .unwrap();
    fixture.fire(true, std::slice::from_ref(&old)).await;
    tokio::time::timeout(Duration::from_secs(2), fixture.entered.notified())
        .await
        .unwrap();
    let current = migrate(&fixture, &old).await;
    assert_eq!(
        current.last_notified_observation.as_ref().unwrap().sample(),
        &CovSample::new(&PropertyValue::Real(10.0)).unwrap(),
        "confirmed admission established the baseline before route migration"
    );
    assert!(fixture
        .table
        .write()
        .await
        .set_last_notified_observation(&current, observation(99.0)));
    assert_eq!(
        fixture.routes.lock().unwrap().as_slice(),
        std::slice::from_ref(&old.subscriber_mac)
    );
    let frame = fixture.sent.lock().unwrap()[0].clone();
    let npdu = decode_npdu(frame).unwrap();
    assert_eq!(npdu.destination, old.subscriber_network);
    let Apdu::ConfirmedRequest(request) = decode_apdu(npdu.payload).unwrap() else {
        panic!("confirmed Multiple");
    };
    fixture.release.add_permits(1);
    assert!(fixture.transactions.admit_terminal(
        &old.subscriber_mac,
        old.subscriber_network.as_ref(),
        &Apdu::SimpleAck(SimpleAck {
            invoke_id: request.invoke_id,
            service_choice: request.service_choice
        })
    ));
    fixture.finish(false).await;
    assert_eq!(
        fixture
            .table
            .read()
            .await
            .get_subscription(old.key())
            .unwrap()
            .last_notified_observation,
        Some(observation(99.0)),
        "late old-route worker/ACK cannot replace a current observation"
    );
}
