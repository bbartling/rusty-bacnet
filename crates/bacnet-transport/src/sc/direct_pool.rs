//! Bounded outbound socket ownership, generation-aware reuse and retirement.
use super::direct_discovery::{DIRECT_POOL_IDLE_TTL, DIRECT_POOL_MAX_ENTRIES};
use super::direct_membership::{disconnect_request, Membership};
use super::WebSocketPort;
use crate::sc_frame::{
    decode_sc_message, encode_sc_message, validate_control, ControlRecipient, ScFunction,
    ScMessage, Vmac,
};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit};

struct SendRequest {
    bytes: Vec<u8>,
    done: oneshot::Sender<Result<(), ()>>,
}

#[derive(Clone)]
pub(crate) struct PooledDirect {
    send: mpsc::Sender<SendRequest>,
    pub(super) member: Arc<Membership>,
    pub(super) uri: String,
    pub(super) peer_max_bvlc_length: u16,
    pub(super) peer_max_apdu_length: u16,
    idle_deadline: Instant,
}

impl PooledDirect {
    pub(super) fn start<W: WebSocketPort>(
        ws: W,
        member: Arc<Membership>,
        uri: String,
        limits: (u16, u16),
        wait: Duration,
        physical: OwnedSemaphorePermit,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (send, mut recv) = mpsc::channel::<SendRequest>(64);
        let owner = Arc::clone(&member);
        let mut retired = owner.retirement();
        // This task is the only physical socket owner. Pool entries and sends
        // hold bounded channel handles, so a replaced socket can really close.
        let task = tokio::spawn(async move {
            let _physical = physical;
            let mut prefer_send = true;
            let locally_retired = loop {
                let event = tokio::select! {
                    biased;
                    _ = async { if !*retired.borrow_and_update() { let _ = retired.changed().await; } } => break true,
                    event = next_event(&ws, &mut recv, prefer_send) => event,
                };
                let request = match event {
                    WorkerEvent::Received(received) => {
                        prefer_send = true;
                        let Ok(wire) = received else {
                            break false;
                        };
                        let Ok(message) = decode_sc_message(&wire) else {
                            continue;
                        };
                        // This is lifecycle control only. Application NPDUs and
                        // unsolicited responses do not enter the transport intake.
                        if message.function != ScFunction::DisconnectRequest {
                            continue;
                        }
                        match validate_control(&message, &wire, ControlRecipient::HubConnector) {
                            Err(Some(nak)) => {
                                if !matches!(
                                    tokio::time::timeout(wait, ws.send(&nak)).await,
                                    Ok(Ok(()))
                                ) {
                                    break false;
                                }
                                continue;
                            }
                            Err(None) => continue,
                            Ok(()) => {}
                        }
                        // Seal new local sends before the bounded ACK write.
                        // Already admitted work is never redirected to a successor.
                        owner.retire();
                        let ack = ScMessage {
                            function: ScFunction::DisconnectAck,
                            message_id: message.message_id,
                            originating_vmac: None,
                            destination_vmac: None,
                            dest_options: Vec::new(),
                            data_options: Vec::new(),
                            payload: bytes::Bytes::new(),
                        };
                        let mut bytes = bytes::BytesMut::new();
                        encode_sc_message(&mut bytes, &ack);
                        let _ = tokio::time::timeout(wait, ws.send(&bytes)).await;
                        break false;
                    }
                    WorkerEvent::Send(request) => {
                        prefer_send = false;
                        match request {
                            Some(r) => r,
                            None => break true,
                        }
                    }
                };
                if !owner.is_current() {
                    break true;
                }
                let result = tokio::select! {
                    biased;
                    _ = retired.changed() => Err(()),
                    result = tokio::time::timeout(wait, ws.send(&request.bytes)) =>
                        result.ok().and_then(Result::ok).ok_or(()),
                };
                let failed = result.is_err();
                let _ = request.done.send(result);
                if failed {
                    break true;
                }
            };
            owner.retire();
            if locally_retired {
                let mut bytes = bytes::BytesMut::new();
                encode_sc_message(&mut bytes, &disconnect_request());
                let _ = tokio::time::timeout(wait, ws.send(&bytes)).await;
            }
            // Dropping ws closes the physical socket; retirement is bounded.
        });
        (
            Self {
                send,
                member,
                uri,
                peer_max_bvlc_length: limits.0,
                peer_max_apdu_length: limits.1,
                idle_deadline: Instant::now() + DIRECT_POOL_IDLE_TTL,
            },
            task,
        )
    }

    pub(super) async fn send(&self, bytes: &[u8]) -> Result<(), ()> {
        let (done, receiver) = oneshot::channel();
        self.member
            .with_current(|| {
                self.send
                    .try_send(SendRequest {
                        bytes: bytes.to_vec(),
                        done,
                    })
                    .map_err(|_| ())
            })
            .ok_or(())??;
        receiver.await.map_err(|_| ())?
    }
}

enum WorkerEvent {
    Received(Result<Vec<u8>, bacnet_types::error::Error>),
    Send(Option<SendRequest>),
}

// Alternate priority after each selected event. A continuously ready receive
// stream can precede a queued send by at most one frame, and a continuously
// filled send queue can precede remote control by at most one bounded write.
// The outer select always gives retirement first priority.
async fn next_event<W: WebSocketPort>(
    ws: &W,
    recv: &mut mpsc::Receiver<SendRequest>,
    prefer_send: bool,
) -> WorkerEvent {
    if prefer_send {
        tokio::select! {
            biased;
            request = recv.recv() => WorkerEvent::Send(request),
            received = ws.recv() => WorkerEvent::Received(received),
        }
    } else {
        tokio::select! {
            biased;
            received = ws.recv() => WorkerEvent::Received(received),
            request = recv.recv() => WorkerEvent::Send(request),
        }
    }
}

pub(crate) struct DirectPool {
    entries: HashMap<Vmac, PooledDirect>,
    order: VecDeque<Vmac>,
}
impl DirectPool {
    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
    pub(crate) fn get(&mut self, vmac: &Vmac, now: Instant) -> Option<PooledDirect> {
        match self.entries.get(vmac) {
            Some(e) if now < e.idle_deadline && e.member.is_current() => Some(e.clone()),
            _ => {
                self.remove(vmac);
                None
            }
        }
    }
    pub(super) fn prune(&mut self, now: Instant) {
        let expired: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, e)| now >= e.idle_deadline || !e.member.is_current())
            .map(|(v, _)| *v)
            .collect();
        for vmac in expired {
            self.remove(&vmac);
        }
    }
    pub(crate) fn insert(&mut self, vmac: Vmac, pooled: PooledDirect) {
        self.remove(&vmac);
        self.order.push_back(vmac);
        self.entries.insert(vmac, pooled);
        while self.entries.len() > DIRECT_POOL_MAX_ENTRIES {
            self.evict_oldest();
        }
    }
    pub(super) fn clear(&mut self) {
        for entry in self.entries.values() {
            entry.member.retire();
        }
        self.entries.clear();
        self.order.clear();
    }
    pub(super) fn evict_oldest(&mut self) {
        if let Some(vmac) = self.order.front().copied() {
            self.remove(&vmac);
        }
    }
    fn remove(&mut self, vmac: &Vmac) {
        if let Some(entry) = self.entries.remove(vmac) {
            entry.member.retire();
        }
        self.order.retain(|v| v != vmac);
    }
    pub(super) fn remove_generation(&mut self, vmac: &Vmac, generation: u64) {
        if self
            .entries
            .get(vmac)
            .is_some_and(|e| e.member.generation == generation)
        {
            self.remove(vmac);
        }
    }
    pub(super) fn refresh(&mut self, vmac: &Vmac, generation: u64, now: Instant) {
        if let Some(entry) = self
            .entries
            .get_mut(vmac)
            .filter(|e| e.member.generation == generation)
        {
            entry.idle_deadline = now + DIRECT_POOL_IDLE_TTL;
        }
    }
    #[cfg(test)]
    pub(crate) fn insert_test_entry<W>(
        &mut self,
        vmac: Vmac,
        _ws: Arc<W>,
        uri: String,
        now: Instant,
    ) {
        use super::direct_membership::{DirectMembership, DirectRole};
        let owner = Arc::new(DirectMembership::default());
        let member = owner
            .reserve([1; 16], vmac, [2; 16], [0xff; 6], DirectRole::Outbound, 16)
            .unwrap()
            .commit();
        let (send, _) = mpsc::channel(1);
        self.insert(
            vmac,
            PooledDirect {
                send,
                member,
                uri,
                peer_max_bvlc_length: 1476,
                peer_max_apdu_length: 1476,
                idle_deadline: now + DIRECT_POOL_IDLE_TTL,
            },
        );
    }
}
impl Drop for DirectPool {
    fn drop(&mut self) {
        for entry in self.entries.values() {
            entry.member.retire();
        }
    }
}

#[cfg(test)]
#[path = "direct_worker_tests.rs"]
mod direct_worker_tests;
