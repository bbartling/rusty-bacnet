//! Timestamped COV-multiple reports carry each change's commit time (#856).
//!
//! The transport advances the Device clock when it sends the WriteProperty
//! SimpleACK. The server always sends that response after the mutation and
//! before its COV fanout, so preparation time differs from commit time without
//! any production hook.
use super::*;
use bacnet_encoding::apdu::{decode_apdu, encode_apdu};
use bacnet_encoding::npdu::{decode_npdu, encode_npdu, Npdu};
use bacnet_objects::analog::AnalogValueObject;
use bacnet_objects::clock::{ClockFrame, ClockReader};
use bacnet_objects::device::{DeviceConfig, DeviceObject};
use bacnet_services::common::PropertyReference;
use bacnet_services::cov_multiple::{
    COVNotificationMultipleRequest, COVNotificationValue, COVReference,
    COVSubscriptionSpecification, SubscribeCOVPropertyMultipleRequest,
};
use bacnet_services::write_property::WritePropertyRequest;
use bacnet_transport::port::{ReceivedNpdu, TransportProvenance};
use bacnet_types::enums::ObjectType;
use bacnet_types::primitives::{Date, Time};
use std::sync::atomic::AtomicBool;
use std::sync::Mutex as StdMutex;
use tokio::sync::mpsc;

const PV: PropertyIdentifier = PropertyIdentifier::PRESENT_VALUE;
const SF: PropertyIdentifier = PropertyIdentifier::STATUS_FLAGS;
const PEER: [u8; 6] = [10, 0, 0, 5, 0xBA, 0xC0];

fn at(second: u8) -> ClockFrame {
    ClockFrame {
        local_date: Date {
            year: 126,
            month: 9,
            day: 29,
            day_of_week: 2,
        },
        local_time: Time {
            hour: 15,
            minute: 0,
            second,
            hundredths: 0,
        },
        utc_offset: 0,
        daylight_savings_status: false,
    }
}

fn time(second: u8) -> Time {
    at(second).local_time
}

#[derive(Clone)]
struct SharedClock(Arc<StdMutex<ClockFrame>>);

impl ClockReader for SharedClock {
    fn read_clock(&self) -> Option<ClockFrame> {
        Some(*self.0.lock().unwrap())
    }
}

type Frames = Arc<StdMutex<Vec<Apdu>>>;

struct ClockTransport {
    incoming: Option<mpsc::Receiver<ReceivedNpdu>>,
    frames: Frames,
    clock: SharedClock,
    /// Device time once a SimpleACK has been sent.
    after_ack: Arc<StdMutex<Option<ClockFrame>>>,
    fail_notifications: Arc<AtomicBool>,
}

impl TransportPort for ClockTransport {
    async fn start(&mut self) -> Result<mpsc::Receiver<ReceivedNpdu>, Error> {
        Ok(self.incoming.take().unwrap())
    }
    async fn stop(&mut self) -> Result<(), Error> {
        Ok(())
    }
    async fn send_unicast(&self, npdu: &[u8], _mac: &[u8]) -> Result<(), Error> {
        let apdu = decode_apdu(decode_npdu(Bytes::copy_from_slice(npdu)).unwrap().payload).unwrap();
        match &apdu {
            Apdu::SimpleAck(_) => {
                if let Some(frame) = self.after_ack.lock().unwrap().take() {
                    *self.clock.0.lock().unwrap() = frame;
                }
            }
            Apdu::UnconfirmedRequest(_) | Apdu::ConfirmedRequest(_)
                if self.fail_notifications.load(Ordering::Acquire) =>
            {
                return Err(Error::Encoding("injected notification send failure".into()));
            }
            _ => {}
        }
        self.frames.lock().unwrap().push(apdu);
        Ok(())
    }
    async fn send_broadcast(&self, _npdu: &[u8]) -> Result<(), Error> {
        Ok(())
    }
    fn local_receive_apdu_capacity(&self) -> u16 {
        1476
    }
    fn local_mac(&self) -> &[u8] {
        &[10, 0, 0, 2, 0xBA, 0xC0]
    }
}

struct Harness {
    server: BACnetServer<ClockTransport>,
    tx: mpsc::Sender<ReceivedNpdu>,
    frames: Frames,
    clock: SharedClock,
    after_ack: Arc<StdMutex<Option<ClockFrame>>>,
    fail_notifications: Arc<AtomicBool>,
    invoke_id: u8,
}

impl Harness {
    async fn start(config: ServerConfig) -> Self {
        let (tx, rx) = mpsc::channel(16);
        let mut db = ObjectDatabase::new();
        db.add(Box::new(
            DeviceObject::new(DeviceConfig {
                instance: 856,
                name: "Timed COV Device".into(),
                max_apdu_length: config.max_apdu_length,
                ..DeviceConfig::default()
            })
            .unwrap(),
        ))
        .unwrap();
        db.add(Box::new(AnalogValueObject::new(1, "AV-1", 62).unwrap()))
            .unwrap();
        let frames = Arc::new(StdMutex::new(Vec::new()));
        let clock = SharedClock(Arc::new(StdMutex::new(at(0))));
        let after_ack = Arc::new(StdMutex::new(None));
        let fail_notifications = Arc::new(AtomicBool::new(false));
        let transport = ClockTransport {
            incoming: Some(rx),
            frames: Arc::clone(&frames),
            clock: clock.clone(),
            after_ack: Arc::clone(&after_ack),
            fail_notifications: Arc::clone(&fail_notifications),
        };
        let server = BACnetServer::start(config, db, transport).await.unwrap();
        // Start installs the system clock; replace it with the test clock.
        server
            .database()
            .write()
            .await
            .set_clock_reader(Some(Arc::new(clock.clone())));
        Self {
            server,
            tx,
            frames,
            clock,
            after_ack,
            fail_notifications,
            invoke_id: 0,
        }
    }

    fn set_clock(&self, second: u8) {
        *self.clock.0.lock().unwrap() = at(second);
    }

    /// Deliver a confirmed request whose response goes out through the
    /// transport, as for a B/IP peer.
    async fn request(&mut self, service_choice: ConfirmedServiceChoice, body: BytesMut) {
        self.invoke_id = self.invoke_id.wrapping_add(1);
        let mut payload = BytesMut::new();
        encode_apdu(
            &mut payload,
            &Apdu::ConfirmedRequest(ConfirmedRequestPdu {
                segmented: false,
                more_follows: false,
                segmented_response_accepted: false,
                max_segments: None,
                max_apdu_length: 1476,
                invoke_id: self.invoke_id,
                sequence_number: None,
                proposed_window_size: None,
                service_choice,
                service_request: body.freeze(),
            }),
        )
        .unwrap();
        let mut npdu = BytesMut::new();
        encode_npdu(
            &mut npdu,
            &Npdu {
                expecting_reply: true,
                payload: payload.freeze(),
                ..Npdu::default()
            },
        )
        .unwrap();
        self.tx
            .send(ReceivedNpdu {
                direct_response: None,
                npdu: npdu.freeze(),
                source_mac: MacAddr::from_slice(&PEER),
                link_layer_group: false,
                data_attributes: Vec::new(),
                provenance: TransportProvenance::unverified(),
                reply_tx: None,
            })
            .await
            .unwrap();
    }

    async fn subscribe(&mut self, confirmed: bool) {
        let mut body = BytesMut::new();
        SubscribeCOVPropertyMultipleRequest {
            subscriber_process_identifier: 856,
            issue_confirmed_notifications: confirmed,
            lifetime: Some(300),
            max_notification_delay: Some(10),
            list_of_cov_subscription_specifications: vec![COVSubscriptionSpecification {
                monitored_object_identifier: av1(),
                list_of_cov_references: vec![COVReference {
                    monitored_property: PropertyReference {
                        property_identifier: PV,
                        property_array_index: None,
                    },
                    cov_increment: Some(0.5),
                    timestamped: true,
                }],
            }],
        }
        .encode(&mut body)
        .unwrap();
        self.request(
            ConfirmedServiceChoice::SUBSCRIBE_COV_PROPERTY_MULTIPLE,
            body,
        )
        .await;
    }

    /// WriteProperty PV at priority 8; the clock moves to `after_ack` when the
    /// SimpleACK is sent, before the server prepares its COV notification.
    async fn write_pv(&mut self, value: f32, after_ack: u8) {
        *self.after_ack.lock().unwrap() = Some(at(after_ack));
        let mut encoded = BytesMut::new();
        bacnet_encoding::primitives::encode_property_value(
            &mut encoded,
            &PropertyValue::Real(value),
        )
        .unwrap();
        let mut body = BytesMut::new();
        WritePropertyRequest {
            object_identifier: av1(),
            property_identifier: PV,
            property_array_index: None,
            property_value: encoded.to_vec(),
            priority: Some(8),
        }
        .encode(&mut body)
        .unwrap();
        self.request(ConfirmedServiceChoice::WRITE_PROPERTY, body)
            .await;
    }

    async fn write_local(&self, value: f32) {
        self.server
            .write_local(
                &av1(),
                PV,
                None,
                PropertyValue::Real(value),
                Some(8),
                crate::LocalCommandSource::ServerDevice,
            )
            .await
            .unwrap();
    }

    /// Wait for the next COV-multiple notification, discarding other frames.
    async fn notification(&self) -> COVNotificationMultipleRequest {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let next = {
                    let mut frames = self.frames.lock().unwrap();
                    let at = frames.iter().position(|apdu| match apdu {
                        Apdu::UnconfirmedRequest(_) => true,
                        Apdu::ConfirmedRequest(request) => {
                            request.service_choice
                                == ConfirmedServiceChoice::CONFIRMED_COV_NOTIFICATION_MULTIPLE
                        }
                        _ => false,
                    });
                    at.map(|at| frames.remove(at))
                };
                match next {
                    Some(Apdu::UnconfirmedRequest(request)) => {
                        return COVNotificationMultipleRequest::decode(&request.service_request)
                            .unwrap()
                    }
                    Some(Apdu::ConfirmedRequest(request)) => {
                        return COVNotificationMultipleRequest::decode(&request.service_request)
                            .unwrap()
                    }
                    _ => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .expect("COV-multiple notification")
    }

    async fn no_notification(&self) {
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        assert!(
            !self
                .frames
                .lock()
                .unwrap()
                .iter()
                .any(|apdu| matches!(apdu, Apdu::UnconfirmedRequest(_))),
            "no notification expected"
        );
    }
}

fn av1() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 1).unwrap()
}

fn real(value: f32) -> Vec<u8> {
    let mut encoded = BytesMut::new();
    bacnet_encoding::primitives::encode_property_value(&mut encoded, &PropertyValue::Real(value))
        .unwrap();
    encoded.to_vec()
}

/// `(property, value bytes, time)` rows of the single monitored object.
fn rows(
    notification: &COVNotificationMultipleRequest,
) -> Vec<(PropertyIdentifier, Vec<u8>, Option<Time>)> {
    assert_eq!(notification.list_of_cov_notifications.len(), 1);
    let item = &notification.list_of_cov_notifications[0];
    assert_eq!(item.monitored_object_identifier, av1());
    item.list_of_values
        .iter()
        .map(
            |COVNotificationValue {
                 property_identifier,
                 value,
                 time_of_change,
                 ..
             }| { (*property_identifier, value.clone(), *time_of_change) },
        )
        .collect()
}

fn pv_rows(notification: &COVNotificationMultipleRequest) -> Vec<(Vec<u8>, Option<Time>)> {
    rows(notification)
        .into_iter()
        .filter(|(property, _, _)| *property == PV)
        .map(|(_, value, time)| (value, time))
        .collect()
}

fn envelope(notification: &COVNotificationMultipleRequest) -> Option<(Date, Time)> {
    notification.timestamp
}

#[tokio::test]
async fn initial_report_carries_admission_time() {
    let mut h = Harness::start(ServerConfig::default()).await;
    h.set_clock(1);
    *h.after_ack.lock().unwrap() = Some(at(2));
    h.subscribe(false).await;
    let initial = h.notification().await;
    assert_eq!(pv_rows(&initial), vec![(real(0.0), Some(time(1)))]);
    assert!(rows(&initial)
        .iter()
        .all(|(_, _, time_of_change)| *time_of_change == Some(time(1))));
    assert_eq!(envelope(&initial), Some((at(1).local_date, time(1))));
    h.server.stop().await.unwrap();
}

#[tokio::test]
async fn write_property_change_reports_commit_time_not_preparation_time() {
    for confirmed in [false, true] {
        let mut h = Harness::start(ServerConfig::default()).await;
        h.subscribe(confirmed).await;
        h.notification().await;
        h.set_clock(10);
        h.write_pv(42.0, 20).await;
        let report = h.notification().await;
        assert_eq!(
            pv_rows(&report),
            vec![(real(42.0), Some(time(10)))],
            "confirmed={confirmed}"
        );
        assert!(rows(&report)
            .iter()
            .all(|(_, _, time_of_change)| *time_of_change == Some(time(10))));
        assert_eq!(envelope(&report), Some((at(10).local_date, time(10))));
        assert_eq!(
            *h.clock.0.lock().unwrap(),
            at(20),
            "prepared after the clock moved"
        );
        h.server.stop().await.unwrap();
    }
}

#[tokio::test]
async fn changes_held_while_notifications_are_suppressed_are_all_reported_in_order() {
    let mut h = Harness::start(ServerConfig::default()).await;
    h.subscribe(false).await;
    h.notification().await;
    // DISABLE_INITIATION suppresses notifications but not local changes.
    h.server.comm_state.store(2, Ordering::Release);
    h.set_clock(11);
    h.write_local(10.0).await;
    h.set_clock(12);
    h.write_local(20.0).await;
    h.no_notification().await;
    h.server.comm_state.store(0, Ordering::Release);
    h.set_clock(13);
    h.write_local(10.0).await;
    let report = h.notification().await;
    assert_eq!(
        pv_rows(&report),
        vec![
            (real(10.0), Some(time(11))),
            (real(20.0), Some(time(12))),
            (real(10.0), Some(time(13))),
        ],
        "A-B-A history is conveyed, each change at its own time"
    );
    let flags: Vec<_> = rows(&report)
        .into_iter()
        .filter(|(property, _, _)| *property == SF)
        .map(|(_, _, time_of_change)| time_of_change)
        .collect();
    assert_eq!(flags, vec![Some(time(11)), Some(time(12)), Some(time(13))]);
    assert_eq!(envelope(&report), Some((at(13).local_date, time(13))));
    h.server.stop().await.unwrap();
}

#[tokio::test]
async fn failed_send_keeps_changes_for_the_next_notification() {
    let mut h = Harness::start(ServerConfig::default()).await;
    h.subscribe(false).await;
    h.notification().await;
    h.fail_notifications.store(true, Ordering::Release);
    h.set_clock(21);
    h.write_local(5.0).await;
    h.no_notification().await;
    h.fail_notifications.store(false, Ordering::Release);
    h.set_clock(22);
    h.write_local(6.0).await;
    let report = h.notification().await;
    assert_eq!(
        pv_rows(&report),
        vec![(real(5.0), Some(time(21))), (real(6.0), Some(time(22)))]
    );
    // Retired once transmitted: an unchanged fanout conveys nothing further.
    h.set_clock(23);
    h.write_local(6.0).await;
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

#[tokio::test]
async fn full_history_drops_the_oldest_changes_and_counts_them() {
    let mut h = Harness::start(ServerConfig {
        max_apdu_length: 128,
        ..ServerConfig::default()
    })
    .await;
    h.subscribe(false).await;
    h.notification().await;
    h.server.comm_state.store(2, Ordering::Release);
    for (second, value) in [(31, 1.0), (32, 2.0), (33, 3.0)] {
        h.set_clock(second);
        h.write_local(value).await;
    }
    let dropped = h.server.cov_counters().timed_changes_dropped;
    assert!(dropped >= 1, "a 128-octet APDU cannot hold three changes");
    h.server.comm_state.store(0, Ordering::Release);
    h.set_clock(34);
    h.write_local(4.0).await;
    let report = h.notification().await;
    let pv = pv_rows(&report);
    assert_eq!(
        pv.last(),
        Some(&(real(4.0), Some(time(34)))),
        "newest change kept"
    );
    assert!(pv.len() < 4, "oldest changes were evicted: {pv:?}");
    assert_eq!(
        pv.first().map(|(_, time_of_change)| *time_of_change),
        Some(Some(time(34 - pv.len() as u8 + 1))),
        "survivors are the most recent changes"
    );
    h.server.stop().await.unwrap();
}
