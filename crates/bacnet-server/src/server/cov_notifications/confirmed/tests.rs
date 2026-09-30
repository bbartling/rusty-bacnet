//! Admission refusals and follow-up budgets of confirmed COV reports (#896),
//! driven straight through the sender and the follow-up fanout.
use super::*;
use crate::cov::{CovNotificationKind, CovSample, CovSubscription};
use crate::server::cov_notify_context::CovNotifyContext;
use crate::server::test_transport::{SendLog, SendMode, TestTransport, BIP_LOCAL_MAC};
use bacnet_objects::analog::AnalogValueObject;
use bacnet_objects::device::{DeviceConfig, DeviceObject};
use std::collections::HashSet;

struct Fixture {
    db: Arc<RwLock<ObjectDatabase>>,
    network: Arc<NetworkLayer<TestTransport>>,
    sent: SendLog,
    table: Arc<RwLock<CovSubscriptionTable>>,
    permits: Arc<Semaphore>,
    transactions: Arc<NotificationTransactions>,
    comm: Arc<AtomicU8>,
    config: ServerConfig,
}

fn av1() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 1).unwrap()
}

/// A confirmed subscription to AV-1: whole-object, or one Multiple reference.
fn proposal(kind: CovNotificationKind, property: PropertyIdentifier) -> CovSubscription {
    CovSubscription {
        subscriber_mac: MacAddr::from_slice(&[127, 0, 0, 1, 0xBA, 0xC1]),
        subscriber_network: None,
        subscriber_process_identifier: 7,
        monitored_object_identifier: av1(),
        issue_confirmed_notifications: true,
        expires_at: Some(Instant::now() + Duration::from_secs(3600)),
        last_notified_observation: None,
        monitored_property: (kind == CovNotificationKind::Multiple).then_some(property),
        monitored_property_array_index: None,
        cov_increment: None,
        notification_kind: kind,
        timestamped: false,
    }
}

impl Fixture {
    fn new(config: ServerConfig) -> Self {
        let mut db = crate::server::clock::clocked_test_database();
        db.add(Box::new(
            DeviceObject::new(DeviceConfig {
                instance: 896,
                name: "Confirmed COV".into(),
                ..DeviceConfig::default()
            })
            .unwrap(),
        ))
        .unwrap();
        db.add(Box::new(AnalogValueObject::new(1, "AV-1", 62).unwrap()))
            .unwrap();
        let transport = TestTransport::builder()
            .local_mac(&BIP_LOCAL_MAC)
            .broadcast(SendMode::Ignore)
            .build();
        let sent = transport.sent();
        Self {
            db: Arc::new(RwLock::new(db)),
            network: Arc::new(NetworkLayer::new(transport)),
            sent,
            table: Arc::new(RwLock::new(CovSubscriptionTable::new())),
            permits: Arc::new(Semaphore::new(255)),
            transactions: NotificationTransactions::new(),
            comm: Arc::new(AtomicU8::new(0)),
            config,
        }
    }

    fn ctx(&self) -> CovNotifyContext<'_, TestTransport> {
        CovNotifyContext {
            db: &self.db,
            network: &self.network,
            cov_table: &self.table,
            cov_in_flight: &self.permits,
            notification_transactions: &self.transactions,
            comm_state: &self.comm,
            config: &self.config,
        }
    }

    async fn admit(&self, sub: CovSubscription) -> CovSubscriptionSnapshot {
        self.table.write().await.admit_for_test(sub, 0).unwrap()
    }

    /// Offer one confirmed report of `sub` to the sender.
    async fn send(&self, sub: &CovSubscriptionSnapshot, budget: &mut EventBudget) {
        let (counters, in_flight_tracker) = {
            let table = self.table.read().await;
            (
                Arc::clone(table.counters()),
                Arc::clone(table.in_flight_tracker()),
            )
        };
        let ctx = self.ctx();
        let observation =
            CovObservation::new(CovSample::new(&PropertyValue::Real(1.0)).unwrap(), None).unwrap();
        BACnetServer::<TestTransport>::send_confirmed_cov(
            &CovFanoutHandles {
                ctx: &ctx,
                in_flight_tracker: &in_flight_tracker,
                counters: &counters,
            },
            budget,
            ConfirmedReport {
                service: ConfirmedServiceChoice::CONFIRMED_COV_NOTIFICATION,
                route: sub.clone(),
                completion: sub.prepare_completion().unwrap(),
                observations: vec![(sub.clone(), observation)],
                claim: None,
            },
            |_| Ok(BytesMut::from(&[0u8; 8][..])),
        )
        .await;
    }

    /// The refused report left no trace: no send, lease, permit, budget or
    /// counter spent.
    async fn untouched(&self, budget: &EventBudget) {
        assert!(self.sent.is_empty());
        assert_eq!(self.transactions.active_count(), 0);
        assert_eq!(self.permits.available_permits(), 255);
        assert_eq!(
            budget.remaining_notifications(),
            self.config.cov_policy.max_notifications_per_event,
            "the budget is refunded"
        );
        let table = self.table.read().await;
        assert_eq!(table.counters().snapshot().notifications_sent, 0);
        assert_eq!(table.in_flight_tracker().active_peer_count(), 0);
    }

    async fn finish(&self) {
        self.transactions.close();
        while let Some(joined) = self.transactions.join_next().await {
            assert!(joined.is_ok() || joined.is_err_and(|error| error.is_cancelled()));
        }
    }
}

#[tokio::test]
async fn a_busy_coordinate_refuses_a_report_and_leaves_the_follow_up_to_it() {
    let f = Fixture::new(ServerConfig::default());
    let single = f
        .admit(proposal(
            CovNotificationKind::Single,
            PropertyIdentifier::PRESENT_VALUE,
        ))
        .await;
    let a = f
        .admit(proposal(
            CovNotificationKind::Multiple,
            PropertyIdentifier::PRESENT_VALUE,
        ))
        .await;
    let b = f
        .admit(proposal(
            CovNotificationKind::Multiple,
            PropertyIdentifier::STATUS_FLAGS,
        ))
        .await;
    // An outstanding report of the subscription, and of a sibling reference.
    let outstanding = {
        let mut table = f.table.write().await;
        [&single, &a].map(|sub| {
            table
                .begin_confirmed(sub.prepare_completion().unwrap(), [sub])
                .unwrap()
        })
    };
    for sub in [&single, &b] {
        let mut budget = EventBudget::new(&f.config.cov_policy);
        f.send(sub, &mut budget).await;
        f.untouched(&budget).await;
        assert!(
            f.table.read().await.revisits().queued().is_empty(),
            "{:?}: the outstanding report owns the follow-up",
            sub.notification_kind
        );
    }
    drop(outstanding);
    f.finish().await;
}

#[tokio::test]
async fn a_fenced_reference_refuses_a_report_and_is_evaluated_again() {
    let f = Fixture::new(ServerConfig::default());
    let single = f
        .admit(proposal(
            CovNotificationKind::Single,
            PropertyIdentifier::PRESENT_VALUE,
        ))
        .await;
    let reference = f
        .admit(proposal(
            CovNotificationKind::Multiple,
            PropertyIdentifier::PRESENT_VALUE,
        ))
        .await;
    // Renewal and re-subscription replace both after they were captured.
    f.admit((*single).clone()).await;
    f.admit((*reference).clone()).await;
    for sub in [&single, &reference] {
        let mut budget = EventBudget::new(&f.config.cov_policy);
        f.send(sub, &mut budget).await;
        f.untouched(&budget).await;
    }
    assert_eq!(
        f.table.read().await.revisits().queued(),
        HashSet::from([single.key().clone(), reference.key().clone()])
    );
    f.finish().await;
}

#[tokio::test]
async fn follow_ups_budget_each_object_and_context_separately() {
    let mut config = ServerConfig::default();
    config.cov_policy.max_notifications_per_event = 1;
    let f = Fixture::new(config);
    let single = f
        .admit(proposal(
            CovNotificationKind::Single,
            PropertyIdentifier::PRESENT_VALUE,
        ))
        .await;
    let reference = f
        .admit(proposal(
            CovNotificationKind::Multiple,
            PropertyIdentifier::PRESENT_VALUE,
        ))
        .await;
    // Each owes a first report; one shared budget of one would drop the second.
    BACnetServer::<TestTransport>::fire_cov_revisits(
        &f.ctx(),
        &[single.key().clone(), reference.key().clone()],
    )
    .await;
    tokio::time::timeout(Duration::from_secs(1), f.sent.wait_for_len(2))
        .await
        .expect("a report per object and per context");
    let services: HashSet<_> = f
        .sent
        .frames()
        .iter()
        .map(|frame| match frame.apdu() {
            Apdu::ConfirmedRequest(request) => request.service_choice,
            other => panic!("expected a confirmed notification: {other:?}"),
        })
        .collect();
    assert_eq!(
        services,
        HashSet::from([
            ConfirmedServiceChoice::CONFIRMED_COV_NOTIFICATION,
            ConfirmedServiceChoice::CONFIRMED_COV_NOTIFICATION_MULTIPLE,
        ])
    );
    let counters = f.table.read().await.counters().snapshot();
    assert_eq!(counters.notifications_throttled_fanout, 0);
    f.finish().await;
}
