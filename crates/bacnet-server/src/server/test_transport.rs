//! The one `TransportPort` double shared by the crate's unit tests (#904).
//!
//! `BACnetServer<T>` and `NetworkLayer<T>` are generic over their transport, so
//! every distinct test transport type compiles the whole server, and every task
//! it spawns, again. In-crate tests therefore share this single non-generic
//! [`TestTransport`] and customise it at runtime: plain builder fields, the
//! [`StartMode`] and [`SendMode`] enums, the built-in send controls on
//! [`TestTransportHandle`], and hooks stored as `Arc<dyn Fn ..>`. Builder
//! methods that take a closure erase it at once, so no closure type ever
//! reaches `TestTransport` or the server.
//!
//! Every send runs this pipeline:
//! 1. The [`SendMode`] for its kind (unicast or broadcast): `Ignore` returns
//!    `Ok(())` untouched and `Panic` panics.
//! 2. The frame is appended to the [`SendLog`], then copied to the
//!    [`TestTransportBuilder::report_to`] channel, if any.
//! 3. The [`TestTransportBuilder::on_send`] hook, if any, runs to completion;
//!    its error ends the send.
//! 4. Built-in controls: a pending `fail_next_send` is taken; a blocked send
//!    (`block_sends` or `block_next_send`) signals `wait_blocked` and waits for
//!    one `release_sends` permit; then the send fails if `fail_next_send` was
//!    taken or `fail_sends` is set.

use std::any::Any;
use std::future::Future;
use std::net::SocketAddrV4;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use bacnet_encoding::apdu::{decode_apdu, Apdu};
use bacnet_encoding::npdu::{decode_npdu, Npdu};
use bacnet_transport::port::{DataAttribute, ReceivedNpdu, TransportPort};
use bacnet_types::error::Error;
use bacnet_types::MacAddr;
use bytes::Bytes;
use tokio::sync::{mpsc, Notify, Semaphore};

/// The boxed future a send or stop hook returns.
pub(crate) type HookFuture = Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>;

type SendHook = Arc<dyn Fn(SentFrame) -> HookFuture + Send + Sync>;
type StopHook = Arc<dyn Fn() -> HookFuture + Send + Sync>;
type Callback = Arc<dyn Fn() + Send + Sync>;
type MacPredicate = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;
type EndpointHook = Arc<dyn Fn() -> Option<SocketAddrV4> + Send + Sync>;

/// A B/IP-shaped local MAC (127.0.0.1:47808) for tests that want six octets.
pub(crate) const BIP_LOCAL_MAC: [u8; 6] = [127, 0, 0, 1, 0xBA, 0xC0];

/// One NPDU handed to the transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SentFrame {
    /// The NPDU bytes exactly as sent.
    pub(crate) npdu: Bytes,
    /// Destination MAC. Empty for a broadcast.
    pub(crate) mac: MacAddr,
    /// Whether this was `send_broadcast`.
    pub(crate) broadcast: bool,
    /// Data attributes passed with the send (empty for the plain send calls).
    pub(crate) data_attributes: Vec<DataAttribute>,
}

impl SentFrame {
    /// Decode the NPDU, panicking on malformed bytes.
    pub(crate) fn decode_npdu(&self) -> Npdu {
        decode_npdu(self.npdu.clone()).expect("sent frame should decode as NPDU")
    }

    /// Decode the APDU the NPDU carries, panicking on malformed bytes.
    pub(crate) fn apdu(&self) -> Apdu {
        decode_apdu(self.decode_npdu().payload).expect("sent NPDU should carry an APDU")
    }
}

/// How `start` behaves.
pub(crate) enum StartMode {
    /// Return a receiver whose sender is already gone: the link is closed.
    Closed,
    /// Return this receiver, which the test feeds. A second start fails.
    Inbound(mpsc::Receiver<ReceivedNpdu>),
    /// Never complete.
    Pending,
    /// Fail with `Error::Encoding` carrying this message.
    Fail(&'static str),
    /// Panic with this message, for tests proving startup is never reached.
    Panic(&'static str),
}

/// What one kind of send (unicast or broadcast) does.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SendMode {
    /// Run the full pipeline (record, report, hook, built-in controls).
    Record,
    /// Return `Ok(())` without recording or running anything.
    Ignore,
    /// Panic with this message.
    Panic(&'static str),
}

/// Shared, cloneable log of recorded sends.
#[derive(Clone, Default)]
pub(crate) struct SendLog {
    inner: Arc<LogInner>,
}

#[derive(Default)]
struct LogInner {
    frames: Mutex<Vec<SentFrame>>,
    pushed: Notify,
}

impl SendLog {
    /// Lock the underlying frames for in-place inspection or mutation.
    pub(crate) fn lock(&self) -> MutexGuard<'_, Vec<SentFrame>> {
        self.inner.frames.lock().unwrap()
    }

    /// Append a frame. The transport does this itself; hooks may record extra.
    pub(crate) fn push(&self, frame: SentFrame) {
        self.lock().push(frame);
        self.inner.pushed.notify_waiters();
    }

    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Snapshot of every recorded frame.
    pub(crate) fn frames(&self) -> Vec<SentFrame> {
        self.lock().clone()
    }

    /// The frame at `index`, panicking when absent.
    pub(crate) fn frame(&self, index: usize) -> SentFrame {
        self.lock()[index].clone()
    }

    /// Remove and return every recorded frame.
    pub(crate) fn take(&self) -> Vec<SentFrame> {
        std::mem::take(&mut *self.lock())
    }

    pub(crate) fn clear(&self) {
        self.lock().clear();
    }

    /// Recorded unicast frames, in order.
    pub(crate) fn unicasts(&self) -> Vec<SentFrame> {
        self.lock()
            .iter()
            .filter(|f| !f.broadcast)
            .cloned()
            .collect()
    }

    /// Recorded broadcast frames, in order.
    pub(crate) fn broadcasts(&self) -> Vec<SentFrame> {
        self.lock()
            .iter()
            .filter(|f| f.broadcast)
            .cloned()
            .collect()
    }

    /// NPDU bytes of every recorded frame.
    pub(crate) fn npdus(&self) -> Vec<Bytes> {
        self.lock().iter().map(|f| f.npdu.clone()).collect()
    }

    /// Decoded APDU of every recorded frame.
    pub(crate) fn apdus(&self) -> Vec<Apdu> {
        self.lock().iter().map(SentFrame::apdu).collect()
    }

    /// Wait until at least `len` frames are recorded. Callers add a timeout.
    pub(crate) async fn wait_for_len(&self, len: usize) {
        loop {
            let pushed = self.inner.pushed.notified();
            if self.len() >= len {
                return;
            }
            pushed.await;
        }
    }
}

struct Shared {
    sent: SendLog,
    starts: AtomicUsize,
    stops: AtomicUsize,
    aborts: AtomicUsize,
    drops: AtomicUsize,
    fail: AtomicBool,
    fail_next: AtomicBool,
    block: AtomicBool,
    block_next: AtomicBool,
    blocked: Semaphore,
    release: Semaphore,
}

impl Default for Shared {
    fn default() -> Self {
        Self {
            sent: SendLog::default(),
            starts: AtomicUsize::new(0),
            stops: AtomicUsize::new(0),
            aborts: AtomicUsize::new(0),
            drops: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
            fail_next: AtomicBool::new(false),
            block: AtomicBool::new(false),
            block_next: AtomicBool::new(false),
            blocked: Semaphore::new(0),
            release: Semaphore::new(0),
        }
    }
}

impl Shared {
    async fn controls(&self) -> Result<(), Error> {
        let fail_once = self.fail_next.swap(false, Ordering::SeqCst);
        if self.block_next.swap(false, Ordering::SeqCst) || self.block.load(Ordering::SeqCst) {
            self.blocked.add_permits(1);
            self.release.acquire().await.unwrap().forget();
        }
        if fail_once || self.fail.load(Ordering::SeqCst) {
            return Err(Error::Encoding(
                "injected test transport send failure".into(),
            ));
        }
        Ok(())
    }
}

/// Cloneable view of a transport's log, counters and built-in send controls.
///
/// Take it from the builder or the transport before the transport moves into
/// the server; `server.test_network().transport().handle()` also works.
#[derive(Clone)]
pub(crate) struct TestTransportHandle {
    shared: Arc<Shared>,
}

impl TestTransportHandle {
    pub(crate) fn sent(&self) -> SendLog {
        self.shared.sent.clone()
    }

    /// Calls to `start`, counted before the start mode runs.
    pub(crate) fn starts(&self) -> usize {
        self.shared.starts.load(Ordering::SeqCst)
    }

    pub(crate) fn stops(&self) -> usize {
        self.shared.stops.load(Ordering::SeqCst)
    }

    pub(crate) fn aborts(&self) -> usize {
        self.shared.aborts.load(Ordering::SeqCst)
    }

    pub(crate) fn drops(&self) -> usize {
        self.shared.drops.load(Ordering::SeqCst)
    }

    /// Fail every recorded send while set.
    pub(crate) fn fail_sends(&self, fail: bool) {
        self.shared.fail.store(fail, Ordering::SeqCst);
    }

    /// Fail the next recorded send only.
    pub(crate) fn fail_next_send(&self) {
        self.shared.fail_next.store(true, Ordering::SeqCst);
    }

    /// Hold every recorded send while set, until released.
    pub(crate) fn block_sends(&self, block: bool) {
        self.shared.block.store(block, Ordering::SeqCst);
    }

    /// Hold the next recorded send only, until released.
    pub(crate) fn block_next_send(&self) {
        self.shared.block_next.store(true, Ordering::SeqCst);
    }

    /// Let `permits` held sends (current or future) continue.
    pub(crate) fn release_sends(&self, permits: usize) {
        self.shared.release.add_permits(permits);
    }

    /// Wait until one more send has become held. Each held send is counted
    /// once, so a send held before the wait still satisfies it.
    pub(crate) async fn wait_blocked(&self) {
        self.shared.blocked.acquire().await.unwrap().forget();
    }
}

#[derive(Default)]
struct Hooks {
    on_start: Option<Callback>,
    on_send: Option<SendHook>,
    on_stop: Option<StopHook>,
    on_drop: Option<Callback>,
    is_broadcast_mac: Option<MacPredicate>,
    bip_broadcast_endpoint: Option<EndpointHook>,
}

enum Start {
    Closed,
    Inbound(Option<mpsc::Receiver<ReceivedNpdu>>),
    Pending,
    Fail(&'static str),
    Panic(&'static str),
}

/// The shared, non-generic test transport. See the module docs.
pub(crate) struct TestTransport {
    local_mac: MacAddr,
    receive_capacity: u16,
    egress_limit: u16,
    broadcast_macs: Vec<MacAddr>,
    bip_broadcast_endpoint: Option<SocketAddrV4>,
    start: Start,
    unicast: SendMode,
    broadcast: SendMode,
    report: Option<mpsc::UnboundedSender<SentFrame>>,
    hooks: Hooks,
    state: Option<Arc<dyn Any + Send + Sync>>,
    shared: Arc<Shared>,
}

impl TestTransport {
    /// A closed link with local MAC `[1]` that records every send and succeeds.
    pub(crate) fn new() -> Self {
        Self::builder().build()
    }

    /// A transport whose `start` panics, for tests that fail before startup.
    pub(crate) fn never_start() -> Self {
        Self::builder()
            .start(StartMode::Panic("test transport must never start"))
            .build()
    }

    /// [`Self::new`] plus its send log.
    pub(crate) fn recording() -> (Self, SendLog) {
        let transport = Self::new();
        let sent = transport.sent();
        (transport, sent)
    }

    /// [`Self::new`] fed by an inbound channel of `capacity`.
    pub(crate) fn inbound(capacity: usize) -> (Self, mpsc::Sender<ReceivedNpdu>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self::builder().inbound(rx).build(), tx)
    }

    pub(crate) fn builder() -> TestTransportBuilder {
        TestTransportBuilder {
            transport: Self {
                local_mac: MacAddr::from_slice(&[1]),
                receive_capacity: 1476,
                egress_limit: 1476,
                broadcast_macs: Vec::new(),
                bip_broadcast_endpoint: None,
                start: Start::Closed,
                unicast: SendMode::Record,
                broadcast: SendMode::Record,
                report: None,
                hooks: Hooks::default(),
                state: None,
                shared: Arc::default(),
            },
        }
    }

    pub(crate) fn handle(&self) -> TestTransportHandle {
        TestTransportHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    pub(crate) fn sent(&self) -> SendLog {
        self.shared.sent.clone()
    }

    /// The value attached with [`TestTransportBuilder::state`], for tests that
    /// only hold the server. Panics when absent or of another type.
    pub(crate) fn state<T: Any + Send + Sync>(&self) -> &T {
        self.state
            .as_deref()
            .and_then(|state| state.downcast_ref::<T>())
            .expect("test transport state is missing or has another type")
    }

    async fn send_frame(&self, mode: SendMode, frame: SentFrame) -> Result<(), Error> {
        match mode {
            SendMode::Record => {}
            SendMode::Ignore => return Ok(()),
            SendMode::Panic(message) => panic!("{message}"),
        }
        self.shared.sent.push(frame.clone());
        if let Some(report) = &self.report {
            let _ = report.send(frame.clone());
        }
        if let Some(hook) = &self.hooks.on_send {
            hook(frame).await?;
        }
        self.shared.controls().await
    }

    fn frame(npdu: &[u8], mac: &[u8], broadcast: bool, attributes: &[DataAttribute]) -> SentFrame {
        SentFrame {
            npdu: Bytes::copy_from_slice(npdu),
            mac: MacAddr::from_slice(mac),
            broadcast,
            data_attributes: attributes.to_vec(),
        }
    }
}

impl Drop for TestTransport {
    fn drop(&mut self) {
        self.shared.drops.fetch_add(1, Ordering::SeqCst);
        if let Some(hook) = &self.hooks.on_drop {
            hook();
        }
    }
}

impl TransportPort for TestTransport {
    fn bip_broadcast_endpoint(&self) -> Option<SocketAddrV4> {
        match &self.hooks.bip_broadcast_endpoint {
            Some(hook) => hook(),
            None => self.bip_broadcast_endpoint,
        }
    }

    async fn start(&mut self) -> Result<mpsc::Receiver<ReceivedNpdu>, Error> {
        self.shared.starts.fetch_add(1, Ordering::SeqCst);
        if let Some(hook) = &self.hooks.on_start {
            hook();
        }
        match &mut self.start {
            Start::Closed => Ok(mpsc::channel(1).1),
            Start::Inbound(receiver) => receiver
                .take()
                .ok_or_else(|| Error::Encoding("test transport already started".into())),
            Start::Pending => std::future::pending().await,
            Start::Fail(message) => Err(Error::Encoding((*message).into())),
            Start::Panic(message) => panic!("{message}"),
        }
    }

    async fn stop(&mut self) -> Result<(), Error> {
        self.shared.stops.fetch_add(1, Ordering::SeqCst);
        match &self.hooks.on_stop {
            Some(hook) => hook().await,
            None => Ok(()),
        }
    }

    fn abort(&mut self) {
        self.shared.aborts.fetch_add(1, Ordering::SeqCst);
    }

    async fn send_unicast(&self, npdu: &[u8], mac: &[u8]) -> Result<(), Error> {
        self.send_frame(self.unicast, Self::frame(npdu, mac, false, &[]))
            .await
    }

    async fn send_unicast_with_data_attributes<'a>(
        &'a self,
        npdu: &'a [u8],
        mac: &'a [u8],
        data_attributes: &'a [DataAttribute],
    ) -> Result<(), Error> {
        let frame = Self::frame(npdu, mac, false, data_attributes);
        self.send_frame(self.unicast, frame).await
    }

    async fn send_broadcast(&self, npdu: &[u8]) -> Result<(), Error> {
        self.send_frame(self.broadcast, Self::frame(npdu, &[], true, &[]))
            .await
    }

    async fn send_broadcast_with_data_attributes<'a>(
        &'a self,
        npdu: &'a [u8],
        data_attributes: &'a [DataAttribute],
    ) -> Result<(), Error> {
        let frame = Self::frame(npdu, &[], true, data_attributes);
        self.send_frame(self.broadcast, frame).await
    }

    fn local_mac(&self) -> &[u8] {
        &self.local_mac
    }

    fn local_receive_apdu_capacity(&self) -> u16 {
        self.receive_capacity
    }

    fn egress_apdu_limit(&self) -> u16 {
        self.egress_limit
    }

    fn is_broadcast_mac(&self, mac: &[u8]) -> bool {
        match &self.hooks.is_broadcast_mac {
            Some(hook) => hook(mac),
            None => self.broadcast_macs.iter().any(|b| b.as_slice() == mac),
        }
    }
}

/// Configures a [`TestTransport`]. Defaults: local MAC `[1]`, capacity and
/// egress limit 1476, [`StartMode::Closed`], [`SendMode::Record`] for both
/// kinds, no broadcast MACs, no B/IP endpoint, no hooks.
pub(crate) struct TestTransportBuilder {
    transport: TestTransport,
}

impl TestTransportBuilder {
    pub(crate) fn local_mac(mut self, mac: &[u8]) -> Self {
        self.transport.local_mac = MacAddr::from_slice(mac);
        self
    }

    pub(crate) fn receive_capacity(mut self, capacity: u16) -> Self {
        self.transport.receive_capacity = capacity;
        self
    }

    pub(crate) fn egress_limit(mut self, limit: u16) -> Self {
        self.transport.egress_limit = limit;
        self
    }

    /// Add a MAC that `is_broadcast_mac` recognises (unless a hook overrides).
    pub(crate) fn broadcast_mac(mut self, mac: &[u8]) -> Self {
        self.transport.broadcast_macs.push(MacAddr::from_slice(mac));
        self
    }

    /// Decide `is_broadcast_mac` with a hook instead of the MAC list.
    pub(crate) fn on_is_broadcast_mac(
        mut self,
        hook: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.transport.hooks.is_broadcast_mac = Some(Arc::new(hook));
        self
    }

    pub(crate) fn bip_broadcast_endpoint(mut self, endpoint: SocketAddrV4) -> Self {
        self.transport.bip_broadcast_endpoint = Some(endpoint);
        self
    }

    /// Answer `bip_broadcast_endpoint` with a hook instead of the fixed value.
    pub(crate) fn on_bip_broadcast_endpoint(
        mut self,
        hook: impl Fn() -> Option<SocketAddrV4> + Send + Sync + 'static,
    ) -> Self {
        self.transport.hooks.bip_broadcast_endpoint = Some(Arc::new(hook));
        self
    }

    pub(crate) fn start(mut self, mode: StartMode) -> Self {
        self.transport.start = match mode {
            StartMode::Closed => Start::Closed,
            StartMode::Inbound(receiver) => Start::Inbound(Some(receiver)),
            StartMode::Pending => Start::Pending,
            StartMode::Fail(message) => Start::Fail(message),
            StartMode::Panic(message) => Start::Panic(message),
        };
        self
    }

    /// Shorthand for `start(StartMode::Inbound(receiver))`.
    pub(crate) fn inbound(self, receiver: mpsc::Receiver<ReceivedNpdu>) -> Self {
        self.start(StartMode::Inbound(receiver))
    }

    pub(crate) fn unicast(mut self, mode: SendMode) -> Self {
        self.transport.unicast = mode;
        self
    }

    pub(crate) fn broadcast(mut self, mode: SendMode) -> Self {
        self.transport.broadcast = mode;
        self
    }

    /// Also send a copy of every recorded frame here. Send errors are ignored.
    pub(crate) fn report_to(mut self, report: mpsc::UnboundedSender<SentFrame>) -> Self {
        self.transport.report = Some(report);
        self
    }

    /// Run a callback at the top of every `start`, before the start mode.
    pub(crate) fn on_start(mut self, hook: impl Fn() + Send + Sync + 'static) -> Self {
        self.transport.hooks.on_start = Some(Arc::new(hook));
        self
    }

    /// Run a hook on every recorded send, after it is logged and before the
    /// built-in controls. The hook's future is part of the send future, so
    /// dropping the send drops it; its error becomes the send's result.
    pub(crate) fn on_send<F>(
        mut self,
        hook: impl Fn(SentFrame) -> F + Send + Sync + 'static,
    ) -> Self
    where
        F: Future<Output = Result<(), Error>> + Send + 'static,
    {
        let hook: SendHook =
            Arc::new(move |frame: SentFrame| -> HookFuture { Box::pin(hook(frame)) });
        self.transport.hooks.on_send = Some(hook);
        self
    }

    /// Replace `stop`'s `Ok(())` with this hook's result (`stops` still counts).
    pub(crate) fn on_stop<F>(mut self, hook: impl Fn() -> F + Send + Sync + 'static) -> Self
    where
        F: Future<Output = Result<(), Error>> + Send + 'static,
    {
        let hook: StopHook = Arc::new(move || -> HookFuture { Box::pin(hook()) });
        self.transport.hooks.on_stop = Some(hook);
        self
    }

    /// Run a callback when the transport is dropped (after `drops` counts).
    pub(crate) fn on_drop(mut self, hook: impl Fn() + Send + Sync + 'static) -> Self {
        self.transport.hooks.on_drop = Some(Arc::new(hook));
        self
    }

    /// Attach test-owned state, read back with [`TestTransport::state`].
    pub(crate) fn state<T: Any + Send + Sync>(mut self, state: Arc<T>) -> Self {
        self.transport.state = Some(state);
        self
    }

    pub(crate) fn handle(&self) -> TestTransportHandle {
        self.transport.handle()
    }

    pub(crate) fn sent(&self) -> SendLog {
        self.transport.sent()
    }

    pub(crate) fn build(self) -> TestTransport {
        self.transport
    }
}

#[path = "test_transport_tests.rs"]
mod tests;
