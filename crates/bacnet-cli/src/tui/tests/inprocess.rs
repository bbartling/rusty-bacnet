//! Real `BACnetServer`s and a `BACnetClient` on an in-memory network, driven
//! through the worker and `update` exactly as the UI loop drives them, minus
//! the terminal.
//!
//! The hub gives every port a 6-byte MAC shaped like a BACnet/IP address, so
//! frames read like a real site and stay the same on every run.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bacnet_client::client::BACnetClient;
use bacnet_objects::database::ObjectDatabase;
use bacnet_objects::device::{DeviceConfig, DeviceObject};
use bacnet_server::server::BACnetServer;
use bacnet_transport::port::{ReceivedNpdu, TransportPort};
use bacnet_types::error::Error;
use bacnet_types::MacAddr;
use bytes::Bytes;
use insta::assert_snapshot;
use ratatui::crossterm::event::KeyCode;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::*;
use crate::tui::app::{Link, OpState};
use crate::tui::worker::{session, EventSink, EVENT_CHANNEL_CAPACITY};

/// Every port sees every broadcast; a unicast reaches the port with that MAC.
#[derive(Default)]
struct Hub {
    ports: Mutex<Vec<(MacAddr, mpsc::Sender<ReceivedNpdu>)>>,
}

struct HubPort {
    hub: Arc<Hub>,
    mac: MacAddr,
    rx: Option<mpsc::Receiver<ReceivedNpdu>>,
}

impl HubPort {
    fn join(hub: &Arc<Hub>, ip: [u8; 4]) -> Self {
        let mac = MacAddr::from_slice(&[ip[0], ip[1], ip[2], ip[3], 0xBA, 0xC0]);
        let (tx, rx) = mpsc::channel(256);
        hub.ports.lock().unwrap().push((mac.clone(), tx));
        Self {
            hub: Arc::clone(hub),
            mac,
            rx: Some(rx),
        }
    }

    fn deliver(&self, npdu: &[u8], to: Option<&[u8]>) {
        let targets: Vec<_> = self
            .hub
            .ports
            .lock()
            .unwrap()
            .iter()
            .filter(|(mac, _)| *mac != self.mac && to.is_none_or(|to| mac.as_slice() == to))
            .map(|(_, tx)| tx.clone())
            .collect();
        for tx in targets {
            let npdu = ReceivedNpdu::unverified(
                Bytes::copy_from_slice(npdu),
                self.mac.clone(),
                to.is_none(),
                Vec::new(),
                None,
            );
            let _ = tx.try_send(npdu);
        }
    }
}

impl TransportPort for HubPort {
    async fn start(&mut self) -> Result<mpsc::Receiver<ReceivedNpdu>, Error> {
        self.rx
            .take()
            .ok_or_else(|| Error::Encoding("hub port already started".into()))
    }

    async fn stop(&mut self) -> Result<(), Error> {
        Ok(())
    }

    async fn send_unicast(&self, npdu: &[u8], mac: &[u8]) -> Result<(), Error> {
        self.deliver(npdu, Some(mac));
        Ok(())
    }

    async fn send_broadcast(&self, npdu: &[u8]) -> Result<(), Error> {
        self.deliver(npdu, None);
        Ok(())
    }

    fn local_mac(&self) -> &[u8] {
        &self.mac
    }

    fn local_receive_apdu_capacity(&self) -> u16 {
        1476
    }
}

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("in-process TUI test exceeded its deadline")
}

/// A site: servers on the hub, the client's worker, and the UI state.
struct Site {
    servers: Vec<BACnetServer<HubPort>>,
    app: App,
    events: mpsc::Receiver<WorkerEvent>,
    commands: Option<mpsc::Sender<Command>>,
    worker: Option<JoinHandle<()>>,
}

impl Site {
    /// Servers `(last IP octet, device instance)`, and a connected client at
    /// 10.0.0.1.
    async fn start(devices: &[(u8, u32)]) -> Self {
        let hub = Arc::new(Hub::default());
        let mut servers = Vec::new();
        for &(octet, instance) in devices {
            let mut db = ObjectDatabase::new();
            db.add(Box::new(
                DeviceObject::new(DeviceConfig {
                    instance,
                    name: format!("Lab device {instance}"),
                    ..Default::default()
                })
                .unwrap(),
            ))
            .unwrap();
            let server = BACnetServer::generic_builder()
                .transport(HubPort::join(&hub, [10, 0, 0, octet]))
                .database(db);
            servers.push(bounded(Box::pin(server.build())).await.unwrap());
        }
        let client = BACnetClient::generic_builder()
            .transport(HubPort::join(&hub, [10, 0, 0, 1]))
            .apdu_timeout_ms(2_000);
        let client = bounded(Box::pin(client.build())).await.unwrap();

        let (sink, events) = EventSink::channel(EVENT_CHANNEL_CAPACITY);
        let (commands, command_rx) = mpsc::channel(16);
        let worker = tokio::spawn(Box::pin(session::serve(
            client,
            AddressStyle::Bip,
            sink,
            command_rx,
        )));
        let mut site = Self {
            servers,
            app: new_app(None),
            events,
            commands: Some(commands),
            worker: Some(worker),
        };
        site.pump_until(|app| matches!(app.link, Link::Up { .. }))
            .await;
        site
    }

    /// Hand commands to the worker, as the UI loop does.
    async fn send(&self, commands: Vec<Command>) {
        for command in commands {
            self.commands.as_ref().unwrap().send(command).await.unwrap();
        }
    }

    /// Apply worker events until `done` holds.
    async fn pump_until(&mut self, done: impl Fn(&App) -> bool) {
        bounded(async {
            while !done(&self.app) {
                let event = self.events.recv().await.expect("worker stopped");
                let commands = worker(&mut self.app, event);
                self.send(commands).await;
            }
        })
        .await;
    }

    /// Fill in the Who-Is form through the keymap, with a 2 s listen window,
    /// send it (confirming the warning if one appears), wait out the window,
    /// and then until the table holds at least `rows` devices.
    async fn who_is(&mut self, range: &str, rows: usize) {
        press(&mut self.app, KeyCode::Char('d'));
        press(&mut self.app, KeyCode::Tab);
        type_text(&mut self.app, range);
        press(&mut self.app, KeyCode::Tab);
        press(&mut self.app, KeyCode::Backspace);
        type_text(&mut self.app, "2");
        let mut commands = press(&mut self.app, KeyCode::Enter);
        if commands.is_empty() {
            commands = press(&mut self.app, KeyCode::Enter);
        }
        assert_eq!(commands.len(), 1, "{commands:?}");
        self.send(commands).await;
        self.pump_until(|app| app.op.as_ref().is_some_and(|op| !op.running()))
            .await;
        assert_eq!(self.app.op.as_ref().unwrap().state, OpState::Done);
        // Replies are in memory and arrive within the window; this only keeps
        // a very slow runner from failing on a reply still in flight.
        self.pump_until(|app| app.devices.len() >= rows).await;
    }

    async fn stop(mut self) {
        // Dropping the command sender stops the worker, which stops the client.
        self.commands = None;
        bounded(self.worker.take().unwrap()).await.unwrap();
        for server in &mut self.servers {
            bounded(server.stop()).await.unwrap();
        }
    }
}

const LAB: [(u8, u32); 5] = [(100, 100), (101, 101), (102, 102), (103, 103), (104, 104)];

#[tokio::test]
async fn range_who_is_lists_exactly_the_three_devices_in_range() {
    let mut site = Site::start(&LAB).await;
    site.who_is("101-103", 3).await;
    assert_eq!(visible(&mut site.app), [101, 102, 103]);
    assert_eq!(site.app.op.as_ref().unwrap().replies, 3);
    assert_snapshot!("lab_range_120x40", screen(&mut site.app, 120, 40));
    site.stop().await;
}

#[tokio::test]
async fn unbounded_who_is_lists_all_five_devices() {
    let mut site = Site::start(&LAB).await;
    site.who_is("", 5).await;
    assert_eq!(visible(&mut site.app), [100, 101, 102, 103, 104]);
    let row = site.app.devices.get(104).unwrap();
    assert_eq!(row.address, "10.0.0.104:47808");
    assert_eq!(row.network, None);
    site.stop().await;
}

#[tokio::test]
async fn two_servers_with_one_instance_raise_a_banner_naming_both() {
    let mut site = Site::start(&[(20, 200), (21, 200), (30, 300)]).await;
    site.who_is("", 2).await;
    site.pump_until(|app| !app.duplicates.is_empty()).await;
    assert_eq!(
        site.app.duplicates.lines(),
        ["instance 200 claimed by 10.0.0.20:47808 and 10.0.0.21:47808"]
    );
    let text = screen(&mut site.app, 120, 40);
    assert!(
        text.contains("DUPLICATE instance 200 claimed by 10.0.0.20:47808 and 10.0.0.21:47808"),
        "{text}"
    );
    assert_eq!(
        visible(&mut site.app),
        [200, 300],
        "the client keeps one row"
    );
    site.stop().await;
}
