//! Build the client for the chosen transport, then serve UI commands and
//! forward client notifications until the UI closes the command channel.

use std::time::Duration;

use bacnet_client::client::BACnetClient;
use bacnet_services::who_is::WhoIsRequest;
use bacnet_transport::port::TransportPort;
use bacnet_types::enums::UnconfirmedServiceChoice;
use bacnet_types::error::Error;
use bytes::BytesMut;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::{DeviceFeed, EventSink};
use crate::transport::{self, TransportArgs};
use crate::tui::message::{
    AddressStyle, Command, OpId, OpOutcome, WhoIsScope, WhoIsSpec, WorkerEvent,
};

/// How often the worker checks whether the UI needs a resync.
const RESYNC_EVERY: Duration = Duration::from_secs(1);

/// Which client to build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportKind {
    /// BACnet/IP.
    Bip,
    /// BACnet/IPv6.
    Bip6,
    /// BACnet/SC.
    Sc,
}

impl TransportKind {
    /// Status bar label.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Bip => "BIP",
            Self::Bip6 => "BIP6",
            Self::Sc => "SC",
        }
    }

    /// How this transport's MACs are shown.
    pub(crate) fn style(self) -> AddressStyle {
        match self {
            Self::Bip => AddressStyle::Bip,
            Self::Bip6 => AddressStyle::Bip6,
            Self::Sc => AddressStyle::Hex,
        }
    }
}

/// What the worker needs to connect.
pub(crate) struct ConnectPlan {
    /// The transport.
    pub(crate) kind: TransportKind,
    /// The global flags.
    pub(crate) args: TransportArgs,
    /// Wait for a [`Command::Connect`] from the interface picker first.
    pub(crate) await_interface: bool,
}

/// Start the worker task. Boxed so the transport futures never sit on a
/// small stack.
pub(crate) fn spawn(
    plan: ConnectPlan,
    sink: EventSink,
    commands: mpsc::Receiver<Command>,
) -> JoinHandle<()> {
    tokio::spawn(Box::pin(connect(plan, sink, commands)))
}

async fn connect(plan: ConnectPlan, sink: EventSink, mut commands: mpsc::Receiver<Command>) {
    let mut args = plan.args;
    if plan.await_interface {
        loop {
            match commands.recv().await {
                Some(Command::Connect {
                    interface,
                    broadcast,
                }) => {
                    args.interface = interface;
                    args.broadcast = broadcast;
                    break;
                }
                Some(_) => {}
                None => return,
            }
        }
    }
    let style = plan.kind.style();
    match plan.kind {
        TransportKind::Bip => match Box::pin(transport::build_bip_client(&args)).await {
            Ok(client) => Box::pin(serve(client, style, sink, commands)).await,
            Err(error) => failed(&sink, error).await,
        },
        TransportKind::Bip6 => match Box::pin(transport::build_bip6_client(&args)).await {
            Ok(client) => Box::pin(serve(client, style, sink, commands)).await,
            Err(error) => failed(&sink, error).await,
        },
        #[cfg(feature = "sc-tls")]
        TransportKind::Sc => match Box::pin(transport::build_sc_client(&args)).await {
            Ok(client) => Box::pin(serve(client, style, sink, commands)).await,
            Err(error) => failed(&sink, error).await,
        },
        #[cfg(not(feature = "sc-tls"))]
        TransportKind::Sc => {
            // `tui::run` refuses --sc without the feature before getting here.
            let error = Error::Encoding("BACnet/SC requires the 'sc-tls' feature".into());
            failed(&sink, error).await;
        }
    }
}

async fn failed(sink: &EventSink, error: Error) {
    tracing::error!("connect failed: {error}");
    sink.deliver(WorkerEvent::ConnectFailed {
        error: error.to_string(),
    })
    .await;
}

/// Serve one connected client until the UI drops its command sender.
pub(crate) async fn serve<T: TransportPort + 'static>(
    mut client: BACnetClient<T>,
    style: AddressStyle,
    sink: EventSink,
    mut commands: mpsc::Receiver<Command>,
) {
    let local = style.format(client.local_mac());
    tracing::info!("connected; local address {local}");
    let mut devices = client.device_events();
    let mut collisions = client.device_collision_events();
    if sink.deliver(WorkerEvent::Connected { local }).await {
        let mut feed = DeviceFeed::new(style);
        let mut listening: Option<(OpId, Instant)> = None;
        let mut resync = tokio::time::interval(RESYNC_EVERY);
        resync.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let deadline = listening.map_or_else(far_future, |(_, until)| until);
            tokio::select! {
                command = commands.recv() => match command {
                    Some(Command::WhoIs { op, spec }) => {
                        if let Some((old, _)) = listening.take() {
                            sink.deliver(WorkerEvent::OpFinished { op: old, outcome: OpOutcome::Cancelled }).await;
                        }
                        listening = who_is(&client, &sink, op, &spec).await;
                    }
                    Some(Command::Cancel { op }) => {
                        if listening.is_some_and(|(id, _)| id == op) {
                            listening = None;
                            tracing::info!("Who-Is {op} cancelled");
                            sink.deliver(WorkerEvent::OpFinished { op, outcome: OpOutcome::Cancelled }).await;
                        }
                    }
                    Some(Command::Connect { .. }) => {}
                    None => break,
                },
                received = devices.recv(), if feed.devices_open => feed.on_device(&sink, received),
                received = collisions.recv(), if feed.collisions_open => {
                    if let Some(event) = feed.on_collision(&sink, received) {
                        sink.deliver(event).await;
                    }
                }
                () = tokio::time::sleep_until(deadline), if listening.is_some() => {
                    if let Some((op, _)) = listening.take() {
                        sink.deliver(WorkerEvent::OpFinished { op, outcome: OpOutcome::Completed }).await;
                    }
                }
                _ = resync.tick(), if feed.needs_resync => {
                    let rows = client.discovered_devices().await.iter().map(|d| feed.row(d)).collect();
                    if sink.offer(WorkerEvent::Snapshot(rows)) == super::Offer::Sent {
                        feed.needs_resync = false;
                    }
                }
            }
        }
    }
    if let Err(error) = client.stop().await {
        tracing::warn!("client stop: {error}");
    }
}

fn far_future() -> Instant {
    Instant::now() + Duration::from_secs(86_400)
}

/// Send a Who-Is; on success the listen window to wait out.
async fn who_is<T: TransportPort + 'static>(
    client: &BACnetClient<T>,
    sink: &EventSink,
    op: OpId,
    spec: &WhoIsSpec,
) -> Option<(OpId, Instant)> {
    match send_who_is(client, spec).await {
        Ok(()) => {
            tracing::info!("Who-Is {op} sent ({})", spec.describe());
            sink.deliver(WorkerEvent::WhoIsSent { op }).await;
            Some((op, Instant::now() + spec.listen))
        }
        Err(error) => {
            tracing::warn!("Who-Is {op} failed: {error}");
            sink.deliver(WorkerEvent::OpFinished {
                op,
                outcome: OpOutcome::Failed(error.to_string()),
            })
            .await;
            None
        }
    }
}

async fn send_who_is<T: TransportPort + 'static>(
    client: &BACnetClient<T>,
    spec: &WhoIsSpec,
) -> Result<(), Error> {
    let range = spec.range;
    match &spec.scope {
        WhoIsScope::Local => {
            let mut buf = BytesMut::new();
            WhoIsRequest { range }.encode(&mut buf);
            client
                .broadcast_unconfirmed(UnconfirmedServiceChoice::WHO_IS, &buf)
                .await
        }
        WhoIsScope::Global => client.who_is(range).await,
        WhoIsScope::Directed { mac, .. } => client.who_is_directed(mac, range).await,
        WhoIsScope::Network(dnet) => client.who_is_network(*dnet, range).await,
    }
}
