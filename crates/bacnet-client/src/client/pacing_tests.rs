//! The minimum interval between confirmed requests to one destination,
//! on paused time (#1535).
use std::sync::{Arc, Mutex as StdMutex};

use bacnet_encoding::apdu::{self, encode_apdu, Apdu, SimpleAck};
use bacnet_encoding::npdu::{decode_npdu, encode_npdu, Npdu};
use bacnet_transport::port::{ReceivedNpdu, TransportPort, TransportProvenance};
use bacnet_types::enums::ConfirmedServiceChoice;
use bacnet_types::error::Error;
use bacnet_types::MacAddr;
use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

use super::pacing::{PaceKey, RequestPacer};
use super::{BACnetClient, ConfirmedTarget};

type Sends = Arc<StdMutex<Vec<(Instant, MacAddr)>>>;

const A: &[u8] = &[0x0A];
const B: &[u8] = &[0x0B];

/// Records when each unicast leaves and answers a confirmed request with a
/// SimpleAck from the MAC it went to, at once.
struct RecordingTransport {
    local_mac: MacAddr,
    inbound_tx: mpsc::Sender<ReceivedNpdu>,
    inbound_rx: Option<mpsc::Receiver<ReceivedNpdu>>,
    sends: Sends,
}

impl TransportPort for RecordingTransport {
    async fn start(&mut self) -> Result<mpsc::Receiver<ReceivedNpdu>, Error> {
        Ok(self.inbound_rx.take().expect("started once"))
    }

    async fn stop(&mut self) -> Result<(), Error> {
        Ok(())
    }

    async fn send_unicast(&self, npdu: &[u8], mac: &[u8]) -> Result<(), Error> {
        self.sends
            .lock()
            .unwrap()
            .push((Instant::now(), MacAddr::from_slice(mac)));
        let npdu = decode_npdu(Bytes::copy_from_slice(npdu))?;
        let Apdu::ConfirmedRequest(request) = apdu::decode_apdu(npdu.payload)? else {
            return Ok(());
        };
        let mut apdu_buf = BytesMut::new();
        encode_apdu(
            &mut apdu_buf,
            &Apdu::SimpleAck(SimpleAck {
                invoke_id: request.invoke_id,
                service_choice: request.service_choice,
            }),
        )?;
        let mut npdu_buf = BytesMut::new();
        encode_npdu(
            &mut npdu_buf,
            &Npdu {
                payload: apdu_buf.freeze(),
                ..Npdu::default()
            },
        )?;
        let _ = self
            .inbound_tx
            .send(ReceivedNpdu {
                direct_response: None,
                npdu: npdu_buf.freeze(),
                source_mac: MacAddr::from_slice(mac),
                link_layer_group: false,
                data_attributes: Vec::new(),
                provenance: TransportProvenance::unverified(),
                reply_tx: None,
            })
            .await;
        Ok(())
    }

    async fn send_broadcast(&self, _npdu: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    fn local_receive_apdu_capacity(&self) -> u16 {
        1476
    }

    fn local_mac(&self) -> &[u8] {
        &self.local_mac
    }
}

async fn client(interval_ms: u64) -> (BACnetClient<RecordingTransport>, Sends) {
    let (inbound_tx, inbound_rx) = mpsc::channel(16);
    let sends = Sends::default();
    let transport = RecordingTransport {
        local_mac: MacAddr::from_slice(&[0x01]),
        inbound_tx,
        inbound_rx: Some(inbound_rx),
        sends: Arc::clone(&sends),
    };
    let client = BACnetClient::generic_builder()
        .transport(transport)
        .min_request_interval_ms(interval_ms)
        .build()
        .await
        .unwrap();
    (client, sends)
}

async fn request(client: &BACnetClient<RecordingTransport>, mac: &[u8]) {
    client
        .confirmed_request(mac, ConfirmedServiceChoice::WRITE_PROPERTY, &[0x0C])
        .await
        .unwrap();
}

/// When each request to `mac` left, relative to the first send of all.
fn sent_to(sends: &Sends, mac: &[u8]) -> Vec<Duration> {
    let sends = sends.lock().unwrap();
    let start = sends[0].0;
    sends
        .iter()
        .filter(|(_, to)| to.as_slice() == mac)
        .map(|(at, _)| *at - start)
        .collect()
}

#[tokio::test(start_paused = true)]
async fn requests_to_one_destination_are_spaced_by_the_interval() {
    let (mut client, sends) = client(50).await;
    for _ in 0..3 {
        request(&client, A).await;
    }
    assert_eq!(
        sent_to(&sends, A),
        [
            Duration::ZERO,
            Duration::from_millis(50),
            Duration::from_millis(100)
        ]
    );
    client.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn requests_to_two_destinations_do_not_wait_on_each_other() {
    let (mut client, sends) = client(50).await;
    tokio::join!(request(&client, A), request(&client, B));
    tokio::join!(request(&client, A), request(&client, B));
    let expected = [Duration::ZERO, Duration::from_millis(50)];
    assert_eq!(sent_to(&sends, A), expected);
    assert_eq!(sent_to(&sends, B), expected);
    client.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn an_interval_of_zero_sends_at_once() {
    let (mut client, sends) = client(0).await;
    for _ in 0..3 {
        request(&client, A).await;
    }
    assert_eq!(sent_to(&sends, A), [Duration::ZERO; 3]);
    assert_eq!(client.pacer.remembered(), 0);
    client.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn concurrent_requests_to_one_destination_queue_in_call_order() {
    let pacer = RequestPacer::new(Duration::from_millis(20));
    let key = || PaceKey::of(ConfirmedTarget::Local { mac: A });
    let start = Instant::now();
    let (first, second, third) = tokio::join!(
        async {
            pacer.wait(key()).await;
            Instant::now() - start
        },
        async {
            pacer.wait(key()).await;
            Instant::now() - start
        },
        async {
            pacer.wait(key()).await;
            Instant::now() - start
        },
    );
    assert_eq!(
        [first, second, third],
        [
            Duration::ZERO,
            Duration::from_millis(20),
            Duration::from_millis(40)
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn the_pacer_forgets_idle_destinations_and_stays_bounded() {
    let pacer = RequestPacer::new(Duration::from_millis(10));
    // Routed and local destinations with the same MAC are different devices.
    let routed = PaceKey::of(ConfirmedTarget::Routed {
        router_mac: B,
        dest_network: 5,
        dest_mac: A,
    });
    assert_ne!(routed, PaceKey::of(ConfirmedTarget::Local { mac: A }));

    let many = |n: u32| {
        (0..n).map(|i| {
            PaceKey::of(ConfirmedTarget::Routed {
                router_mac: B,
                dest_network: 1,
                dest_mac: &i.to_be_bytes(),
            })
        })
    };
    // Every destination still inside its interval: the cap holds anyway.
    for key in many(5_000) {
        pacer.wait(key).await;
    }
    assert!(pacer.remembered() <= 4_096);
    // Once they have all been idle a whole interval, a new one sweeps them.
    tokio::time::advance(Duration::from_millis(10)).await;
    pacer.wait(routed).await;
    assert_eq!(pacer.remembered(), 1);
}
