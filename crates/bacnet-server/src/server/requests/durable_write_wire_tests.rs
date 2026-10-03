//! A Notification Forwarder's list saves through the server's request
//! dispatch (#1270): each runs on the forwarder's writer thread while the
//! database guard is dropped, so other requests read and write meanwhile,
//! and a list that cannot be saved is still refused on the wire.
//!
//! DEVICE 0; OPERATIONAL_PROBLEM 25.

use super::mutation_list_wire_tests::{change_list_error, list_request, wire, ADD};
use super::mutation_tests::{oid, Fixture};
use super::*;
use bacnet_encoding::constructed::{
    encode_destination_list, encode_event_notification_subscription_list,
};
use bacnet_objects::notification_forwarder::{
    ForwarderSnapshot, NotificationForwarderObject, NotificationForwarderPersistence,
};
use bacnet_objects::traits::BACnetObject;
use bacnet_services::common::BACnetPropertyValue;
use bacnet_services::wpm::{WriteAccessSpecification, WritePropertyMultipleRequest};
use bacnet_services::write_property::WritePropertyRequest;
use bacnet_types::bitstring::{DaysOfWeek, EventTransitionBits};
use bacnet_types::constructed::{
    BACnetDestination, BACnetEventNotificationSubscription, BACnetRecipient,
};
use bacnet_types::primitives::Time;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex as StdMutex};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(10);
/// How long a reader may wait for the database while a save runs.
const READ_WITHIN: Duration = Duration::from_millis(500);
const SIMPLE_ACK_ADD: [u8; 3] = [0x20, 5, 8];
const SIMPLE_ACK_WRITE: [u8; 3] = [0x20, 5, 15];
const SIMPLE_ACK_WPM: [u8; 3] = [0x20, 5, 16];

/// Forwarder storage whose saves can fail, or wait until the test lets each
/// one go.
#[derive(Default)]
struct HeldStorage {
    saved: StdMutex<Option<ForwarderSnapshot>>,
    saves: AtomicUsize,
    fail: AtomicBool,
    hold: StdMutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
}

impl HeldStorage {
    /// Make every later save report on the first channel and wait for a
    /// message on the second.
    fn hold(&self) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (started, started_rx) = mpsc::channel();
        let (go, go_rx) = mpsc::channel();
        *self.hold.lock().unwrap() = Some((started, go_rx));
        (started_rx, go)
    }
}

impl NotificationForwarderPersistence for HeldStorage {
    fn load(&self, _forwarder: ObjectIdentifier) -> Result<Option<ForwarderSnapshot>, Error> {
        Ok(self.saved.lock().unwrap().clone())
    }

    fn save(
        &self,
        _forwarder: ObjectIdentifier,
        snapshot: &ForwarderSnapshot,
    ) -> Result<(), Error> {
        if let Some((started, go)) = &*self.hold.lock().unwrap() {
            let _ = started.send(());
            let _ = go.recv();
        }
        if self.fail.load(Ordering::SeqCst) {
            return Err(Error::Encoding("storage unavailable".into()));
        }
        *self.saved.lock().unwrap() = Some(snapshot.clone());
        self.saves.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn subscription(instance: u32) -> BACnetEventNotificationSubscription {
    BACnetEventNotificationSubscription {
        recipient: BACnetRecipient::Device(oid(ObjectType::DEVICE, instance)),
        process_identifier: 3,
        issue_confirmed_notifications: false,
        time_remaining: 10,
    }
}

fn framed(subscriptions: &[BACnetEventNotificationSubscription]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    encode_event_notification_subscription_list(&mut buf, subscriptions).unwrap();
    buf.to_vec()
}

fn destination(instance: u32) -> BACnetDestination {
    BACnetDestination {
        valid_days: DaysOfWeek::all(),
        from_time: Time {
            hour: 0,
            minute: 0,
            second: 0,
            hundredths: 0,
        },
        to_time: Time {
            hour: 23,
            minute: 59,
            second: 59,
            hundredths: 99,
        },
        recipient: BACnetRecipient::Device(oid(ObjectType::DEVICE, instance)),
        process_identifier: 1,
        issue_confirmed_notifications: false,
        transitions: EventTransitionBits::all(),
    }
}

/// A fixture holding forwarder 1, kept in `storage`.
async fn fixture(storage: &Arc<HeldStorage>) -> (Arc<Fixture>, ObjectIdentifier) {
    let fixture = Fixture::new(None);
    let forwarder = NotificationForwarderObject::with_persistence(
        1,
        "NF",
        Arc::clone(storage) as Arc<dyn NotificationForwarderPersistence>,
    )
    .unwrap();
    let nf = forwarder.object_identifier();
    fixture.db.write().await.add(Box::new(forwarder)).unwrap();
    (Arc::new(fixture), nf)
}

/// Send `request`, hold its save, and check that the database answers a
/// reader and a writer while the save runs. Returns the response and whether
/// the database answered both in time.
async fn while_saving(
    fixture: &Arc<Fixture>,
    storage: &HeldStorage,
    service: ConfirmedServiceChoice,
    request: Bytes,
) -> (Vec<u8>, bool) {
    let (started, go) = storage.hold();
    let sending = tokio::spawn({
        let fixture = Arc::clone(fixture);
        async move { wire(&fixture, service, request).await }
    });
    tokio::task::spawn_blocking(move || started.recv_timeout(WAIT))
        .await
        .unwrap()
        .expect("the save started");
    let readable = tokio::time::timeout(READ_WITHIN, fixture.db.read())
        .await
        .is_ok();
    let writable = tokio::time::timeout(READ_WITHIN, fixture.db.write())
        .await
        .is_ok();
    go.send(()).unwrap();
    (sending.await.unwrap(), readable && writable)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_add_list_element_save_runs_while_the_database_stays_available() {
    let storage = Arc::new(HeldStorage::default());
    let (fixture, nf) = fixture(&storage).await;
    let request = list_request(
        nf,
        PropertyIdentifier::SUBSCRIBED_RECIPIENTS,
        None,
        &framed(&[subscription(7)]),
    );
    let (response, available) = while_saving(&fixture, &storage, ADD, request).await;
    assert_eq!(response, SIMPLE_ACK_ADD);
    assert!(available, "the database was held while the forwarder saved");
    assert_eq!(
        fixture
            .read(nf, PropertyIdentifier::SUBSCRIBED_RECIPIENTS)
            .await,
        PropertyValue::ApplicationData(framed(&[subscription(7)]))
    );
    // The write took the staged save; it did not save again.
    assert_eq!(storage.saves.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recipient_list_write_property_save_runs_while_the_database_stays_available() {
    let storage = Arc::new(HeldStorage::default());
    let (fixture, nf) = fixture(&storage).await;
    let mut list = BytesMut::new();
    encode_destination_list(&mut list, &[destination(4)]).unwrap();
    let mut request = BytesMut::new();
    WritePropertyRequest {
        object_identifier: nf,
        property_identifier: PropertyIdentifier::RECIPIENT_LIST,
        property_array_index: None,
        property_value: list.to_vec(),
        priority: None,
    }
    .encode(&mut request)
    .unwrap();
    let (response, available) = while_saving(
        &fixture,
        &storage,
        ConfirmedServiceChoice::WRITE_PROPERTY,
        request.freeze(),
    )
    .await;
    assert_eq!(response, SIMPLE_ACK_WRITE);
    assert!(available, "the database was held while the forwarder saved");
    assert_eq!(
        storage
            .saved
            .lock()
            .unwrap()
            .clone()
            .unwrap()
            .recipient_list,
        Some(vec![destination(4)])
    );
    assert_eq!(storage.saves.load(Ordering::SeqCst), 1);
}

fn subscriptions_attempt() -> BACnetPropertyValue {
    BACnetPropertyValue {
        property_identifier: PropertyIdentifier::SUBSCRIBED_RECIPIENTS,
        property_array_index: None,
        value: framed(&[subscription(8)]),
        priority: None,
    }
}

fn wpm(nf: ObjectIdentifier, attempts: Vec<BACnetPropertyValue>) -> Bytes {
    let mut request = BytesMut::new();
    WritePropertyMultipleRequest {
        list_of_write_access_specs: vec![WriteAccessSpecification {
            object_identifier: nf,
            list_of_properties: attempts,
        }],
    }
    .encode(&mut request)
    .unwrap();
    request.freeze()
}

fn wpm_request(nf: ObjectIdentifier) -> Bytes {
    wpm(nf, vec![subscriptions_attempt()])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_property_multiple_stages_a_list_write_that_follows_another_attempt() {
    let storage = Arc::new(HeldStorage::default());
    let (fixture, nf) = fixture(&storage).await;
    let mut description = BytesMut::new();
    bacnet_encoding::primitives::encode_app_character_string(&mut description, "relay").unwrap();
    let request = wpm(
        nf,
        vec![
            BACnetPropertyValue {
                property_identifier: PropertyIdentifier::DESCRIPTION,
                property_array_index: None,
                value: description.to_vec(),
                priority: None,
            },
            subscriptions_attempt(),
        ],
    );
    let (response, available) = while_saving(
        &fixture,
        &storage,
        ConfirmedServiceChoice::WRITE_PROPERTY_MULTIPLE,
        request,
    )
    .await;
    assert_eq!(response, SIMPLE_ACK_WPM);
    assert!(available, "the database was held while the forwarder saved");
    assert_eq!(
        fixture.read(nf, PropertyIdentifier::DESCRIPTION).await,
        PropertyValue::CharacterString("relay".into())
    );
    assert_eq!(storage.saves.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_property_multiple_save_runs_while_the_database_stays_available() {
    let storage = Arc::new(HeldStorage::default());
    let (fixture, nf) = fixture(&storage).await;
    let (response, available) = while_saving(
        &fixture,
        &storage,
        ConfirmedServiceChoice::WRITE_PROPERTY_MULTIPLE,
        wpm_request(nf),
    )
    .await;
    assert_eq!(response, SIMPLE_ACK_WPM);
    assert!(available, "the database was held while the forwarder saved");
    assert_eq!(
        storage
            .saved
            .lock()
            .unwrap()
            .clone()
            .unwrap()
            .subscribed_recipients,
        [subscription(8)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_property_multiple_under_an_authorizer_saves_in_place() {
    // The authorizer sees each attempt only as the handler reaches it, under
    // the guard, so the server cannot stage the save ahead of it.
    let storage = Arc::new(HeldStorage::default());
    let mut fixture = Fixture::new(Some(Arc::new(|_| true)));
    fixture.config.mutation_policy = crate::mutation::MutationPolicy::Permissive;
    let forwarder = NotificationForwarderObject::with_persistence(
        1,
        "NF",
        Arc::clone(&storage) as Arc<dyn NotificationForwarderPersistence>,
    )
    .unwrap();
    let nf = forwarder.object_identifier();
    fixture.db.write().await.add(Box::new(forwarder)).unwrap();
    let fixture = Arc::new(fixture);
    let (response, available) = while_saving(
        &fixture,
        &storage,
        ConfirmedServiceChoice::WRITE_PROPERTY_MULTIPLE,
        wpm_request(nf),
    )
    .await;
    assert_eq!(response, SIMPLE_ACK_WPM);
    assert!(
        !available,
        "an authorized WPM attempt saves under the guard"
    );
    assert_eq!(storage.saves.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_list_that_cannot_be_saved_is_refused_on_the_wire_and_the_old_list_stays() {
    let storage = Arc::new(HeldStorage::default());
    let (fixture, nf) = fixture(&storage).await;
    let added = list_request(
        nf,
        PropertyIdentifier::SUBSCRIBED_RECIPIENTS,
        None,
        &framed(&[subscription(7)]),
    );
    assert_eq!(wire(&fixture, ADD, added).await, SIMPLE_ACK_ADD);
    storage.fail.store(true, Ordering::SeqCst);
    let refused = list_request(
        nf,
        PropertyIdentifier::SUBSCRIBED_RECIPIENTS,
        None,
        &framed(&[subscription(8)]),
    );
    assert_eq!(
        wire(&fixture, ADD, refused).await,
        change_list_error(ADD, 0, 25, 0)
    );
    assert_eq!(
        fixture
            .read(nf, PropertyIdentifier::SUBSCRIBED_RECIPIENTS)
            .await,
        PropertyValue::ApplicationData(framed(&[subscription(7)]))
    );
}
