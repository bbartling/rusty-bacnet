//! What [`BACnetRouter::start`] sets up, and what it hands back (#1220).
//!
//! A router can be started with a tracked local APDU receiver, a wire-control
//! policy and authorizer, and its own network-control receiver, in any
//! combination. [`RouterOptions`] picks them and [`StartedRouter`] carries the
//! receivers that were asked for.

use std::fmt;
use std::marker::PhantomData;

use tokio::sync::mpsc;

use super::control_policy::{ControlAuthorizer, ControlGate, ControlPolicy};
use super::BACnetRouter;
use crate::layer::{
    AdmissionReceiver, QueueAdmissionCounters, ReceivedApdu, ReceivedNetworkControl,
};

/// How [`BACnetRouter::start`] sets up a router.
///
/// [`Self::new`] gives the plain router: a raw local APDU receiver, the
/// permissive wire-control policy with no authorizer, and no network-control
/// receiver. Each builder method turns on one option, and they combine freely.
///
/// `A` is the local APDU receiver type the start returns, a raw
/// [`mpsc::Receiver`] unless [`Self::track_admission`] switches it to an
/// [`AdmissionReceiver`].
///
/// ```no_run
/// # use bacnet_network::router::{BACnetRouter, RouterOptions, RouterPort, StartedRouter};
/// # use bacnet_network::router::control_policy::ControlPolicy;
/// # use bacnet_transport::loopback::LoopbackTransport;
/// # async fn run(ports: Vec<RouterPort<LoopbackTransport>>) -> Result<(), bacnet_types::error::Error> {
/// let options = RouterOptions::new()
///     .track_admission()
///     .control_policy(ControlPolicy::Hardened)
///     .network_control_receiver();
/// let StartedRouter { router, apdus, network_control } =
///     BACnetRouter::start(ports, options).await?;
/// let counters = apdus.counters();
/// # Ok(())
/// # }
/// ```
pub struct RouterOptions<A = mpsc::Receiver<ReceivedApdu>> {
    policy: ControlPolicy,
    authorizer: Option<ControlAuthorizer>,
    network_control: bool,
    apdus: PhantomData<fn() -> A>,
}

impl RouterOptions {
    /// The plain router, with every option off.
    ///
    /// Its local APDU receiver is a raw [`mpsc::Receiver`]. All ports share
    /// one 256-item local queue. Full/Closed admission drops the arriving APDU
    /// with its payload, metadata and reply sender without sending reply bytes
    /// or a wire rejection, never evicting an older item. Admission never
    /// waits for the consumer or stops forwarding/inline control handling.
    /// This raw receiver has no per-source quota, admission snapshot or
    /// depth/high-water tracking. Full/Closed drops are counted internally,
    /// with Closed > Full precedence.
    ///
    /// Closing retains queued items; dropping discards them. Both leave
    /// routing active, and each later local admission attempt counts as
    /// Closed. [`BACnetRouter::stop`] also leaves queued items drainable. Use
    /// [`Self::track_admission`] for snapshots and per-source fairness; see the
    /// [receive-queue contract](crate::layer#receive-queue-admission) for the
    /// raw/tracked matrix and ownership/lifecycle details.
    pub fn new() -> Self {
        Self {
            policy: ControlPolicy::default(),
            authorizer: None,
            network_control: false,
            apdus: PhantomData,
        }
    }
}

impl Default for RouterOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl<A> RouterOptions<A> {
    /// Return the local APDU receiver as an [`AdmissionReceiver`], which
    /// exposes queue-admission snapshots and enforces a per-source quota.
    ///
    /// Routing and the router's lifecycle are unchanged. All ports share one
    /// 256-item queue and one accounting state; [`AdmissionReceiver::counters`]
    /// returns cloneable count-only handles for depth/high-water and
    /// admission-drop totals, readable after receiver or router drop. Failed
    /// admission drops the arriving APDU, never an older one, and releases its
    /// payload, metadata and reply sender without reply bytes or wire
    /// rejections. Forwarding and inline control handling remain independent.
    /// Closing the receiver retains queued items for draining and counts each
    /// subsequent local arrival as a closed drop while forwarding continues.
    /// [`BACnetRouter::stop`] also leaves queued items drainable. Dropping the
    /// receiver discards queued items and releases their reply channels
    /// without sending reply bytes; discarding queued items is not an
    /// admission drop.
    ///
    /// Each ([ingress port network number](ReceivedApdu::ingress_network),
    /// complete [`source_mac`](ReceivedApdu::source_mac) byte value) may hold
    /// at most 16 queued local APDUs, never keyed by routed NPDU SNET/SADR.
    /// Identical MAC bytes on different ports have separate quotas.
    /// Dequeuing releases one slot, even if the consumer retains the APDU.
    /// **Closed > fairness > Full** selects one drop reason; over-quota
    /// arrivals increment
    /// [`fairness_drops`](crate::layer::QueueAdmissionSnapshot::fairness_drops)
    /// even if the queue is also globally full, unless admission is closed.
    /// The raw receiver from [`RouterOptions::new`] does not enforce a quota.
    /// See the [receive-queue contract](crate::layer#receive-queue-admission)
    /// for exact keys, the raw/tracked matrix and complete ownership/lifecycle
    /// rules.
    pub fn track_admission(self) -> RouterOptions<AdmissionReceiver<ReceivedApdu>> {
        RouterOptions {
            policy: self.policy,
            authorizer: self.authorizer,
            network_control: self.network_control,
            apdus: PhantomData,
        }
    }

    /// RB-09: the wire-control policy for state-changing routing controls.
    ///
    /// [`ControlPolicy::Permissive`], the default, admits them.
    /// [`ControlPolicy::Hardened`] denies a protected control unless an
    /// authorizer approves it, as a silent drop. Read the totals with
    /// [`BACnetRouter::control_snapshot`].
    pub fn control_policy(mut self, policy: ControlPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// RB-09: a callback that decides every protected wire control, whatever
    /// the [policy](Self::control_policy). See [`ControlAuthorizer`] for what
    /// it may and may not do.
    pub fn control_authorizer(mut self, authorizer: ControlAuthorizer) -> Self {
        self.authorizer = Some(authorizer);
        self
    }

    /// Also return the router's own network-control receiver (#1175), in
    /// [`StartedRouter::network_control`].
    ///
    /// The receiver gets each Reject-Message-To-Network addressed to the
    /// router itself: one with no DNET, or whose DADR is the router's MAC on
    /// the port attached to that DNET. Such a reject still updates the routing
    /// table and is never relayed. Without this receiver, the table update is
    /// all that happens. Every other network message is still handled inline.
    ///
    /// Records match what a non-router
    /// [`NetworkLayer::enable_network_control_receiver`](crate::layer::NetworkLayer::enable_network_control_receiver)
    /// delivers, numbered from [`BACnetRouter::network_control_ingress_sequence`].
    /// The queue holds 256 controls, apart from the APDU queue. Admission never
    /// waits: a full or closed receiver drops the arriving control, and
    /// routing carries on.
    pub fn network_control_receiver(mut self) -> Self {
        self.network_control = true;
        self
    }

    /// The wire-control gate these options select.
    pub(super) fn control_gate(&self) -> ControlGate {
        ControlGate::new(self.policy, self.authorizer.clone())
    }

    /// Whether [`Self::network_control_receiver`] was asked for.
    pub(super) fn wants_network_control(&self) -> bool {
        self.network_control
    }
}

impl<A> fmt::Debug for RouterOptions<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouterOptions")
            .field("policy", &self.policy)
            .field(
                "authorizer",
                &self.authorizer.as_ref().map(|_| "<callback>"),
            )
            .field("network_control", &self.network_control)
            .field("apdus", &std::any::type_name::<A>())
            .finish()
    }
}

/// A running router and the receivers its [`RouterOptions`] asked for.
pub struct StartedRouter<A = mpsc::Receiver<ReceivedApdu>> {
    /// The router.
    pub router: BACnetRouter,
    /// APDUs for local applications: those without a remote destination, or
    /// for which this router is the final hop.
    pub apdus: A,
    /// The router's own network-control receiver, when
    /// [`RouterOptions::network_control_receiver`] asked for it.
    pub network_control: Option<mpsc::Receiver<ReceivedNetworkControl>>,
}

/// A local APDU receiver type [`BACnetRouter::start`] can return: the raw
/// [`mpsc::Receiver`] or, after [`RouterOptions::track_admission`], an
/// [`AdmissionReceiver`]. Sealed.
pub trait LocalApduReceiver: sealed::Sealed {}

impl LocalApduReceiver for mpsc::Receiver<ReceivedApdu> {}
impl LocalApduReceiver for AdmissionReceiver<ReceivedApdu> {}

pub(super) mod sealed {
    use super::*;

    /// How the start builds each receiver type from the shared local queue.
    pub trait Sealed: Sized {
        /// Whether the queue keeps depth and per-source accounting.
        const TRACKED: bool;

        /// Wrap the queue's receiving end.
        fn from_queue(rx: mpsc::Receiver<ReceivedApdu>, counters: QueueAdmissionCounters) -> Self;
    }

    impl Sealed for mpsc::Receiver<ReceivedApdu> {
        const TRACKED: bool = false;

        fn from_queue(rx: mpsc::Receiver<ReceivedApdu>, _: QueueAdmissionCounters) -> Self {
            rx
        }
    }

    impl Sealed for AdmissionReceiver<ReceivedApdu> {
        const TRACKED: bool = true;

        fn from_queue(rx: mpsc::Receiver<ReceivedApdu>, counters: QueueAdmissionCounters) -> Self {
            AdmissionReceiver::from_apdu_parts(rx, counters)
        }
    }
}

#[cfg(test)]
#[path = "options_tests.rs"]
mod tests;
