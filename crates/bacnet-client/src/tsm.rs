//! Transaction State Machine (TSM) per ASHRAE 135-2020 Clause 5.4.
//!
//! Tracks in-flight confirmed requests. Each request gets a unique invoke_id
//! (0-255) scoped per destination MAC. Responses are delivered via oneshot channels.

use bacnet_types::enums::ConfirmedServiceChoice;
use bacnet_types::MacAddr;
use bytes::Bytes;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{oneshot, watch};

/// TSM configuration.
#[derive(Debug, Clone)]
pub struct TsmConfig {
    /// APDU timeout in milliseconds (default 6000).
    pub apdu_timeout_ms: u64,
    /// APDU segment timeout in milliseconds (default = apdu_timeout_ms).
    pub apdu_segment_timeout_ms: u64,
    /// Number of APDU retries (default 3).
    pub apdu_retries: u8,
}

impl Default for TsmConfig {
    fn default() -> Self {
        Self {
            apdu_timeout_ms: 6000,
            apdu_segment_timeout_ms: 6000,
            apdu_retries: 3,
        }
    }
}

/// Response types that complete a transaction.
///
/// Non-exhaustive: the TSM gains completion reasons as more of Clause 5.4's
/// state machine is implemented, and those should be additive for callers.
#[derive(Debug)]
#[non_exhaustive]
pub enum TsmResponse {
    /// SimpleACK — confirmed service completed with no return data.
    SimpleAck,
    /// ComplexACK — confirmed service returned data.
    ComplexAck { service_data: Bytes },
    /// Error PDU.
    Error { class: u32, code: u32 },
    /// Reject PDU.
    Reject { reason: u8 },
    /// Abort PDU.
    Abort { reason: u8 },
}

/// Invoke ID allocator scoped to a single destination MAC.
struct InvokeIdAllocator {
    next_id: u8,
    in_use: [bool; 256],
}

impl InvokeIdAllocator {
    fn new() -> Self {
        Self {
            next_id: 0,
            in_use: [false; 256],
        }
    }

    fn allocate(&mut self) -> Option<u8> {
        let start = self.next_id;
        loop {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            if !self.in_use[id as usize] {
                self.in_use[id as usize] = true;
                return Some(id);
            }
            if self.next_id == start {
                return None;
            }
        }
    }

    fn release(&mut self, id: u8) {
        self.in_use[id as usize] = false;
    }

    fn all_free(&self) -> bool {
        !self.in_use.iter().any(|&used| used)
    }
}

/// Maximum number of distinct destination MACs tracked by the TSM.
/// Prevents unbounded memory growth from spoofed source addresses.
const MAX_TSM_DESTINATIONS: usize = 1024;

/// What `complete_transaction` did with a response.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompletionOutcome {
    /// The response matched a pending transaction and was delivered.
    Delivered,
    /// No transaction was pending for this source and invoke ID.
    NoTransaction,
    /// A transaction was pending, but the response was labelled for a
    /// different confirmed service. The transaction is left pending and the
    /// invoke ID stays allocated, so the legitimate response can still arrive.
    ServiceChoiceMismatch {
        /// The service the pending request asked for.
        expected: ConfirmedServiceChoice,
        /// The service the response claimed to answer.
        observed: ConfirmedServiceChoice,
    },
}

/// Request-side timer state delivered to the task waiting for a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransactionProgress {
    AwaitingResponse,
    SegmentedResponse { generation: u64 },
}

pub(crate) struct TransactionRegistration {
    pub(crate) response: oneshot::Receiver<TsmResponse>,
    pub(crate) progress: watch::Receiver<TransactionProgress>,
    pub(crate) owner: TransactionOwner,
}

/// Identity of one registration, independent of its reusable wire key.
///
/// Pointer identity is stable while delayed work retains a clone. The
/// allocation therefore cannot be reused for a replacement transaction until
/// every stale owner reference has gone away.
#[derive(Clone)]
pub(crate) struct TransactionOwner(Arc<()>);

impl TransactionOwner {
    fn new() -> Self {
        Self(Arc::new(()))
    }

    pub(crate) fn same_as(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestTimerExpiration {
    Retry,
    SegmentedResponse { generation: u64 },
    TimedOut,
    NoTransaction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SegmentTimerExpiration {
    Activity { generation: u64 },
    AwaitingResponse,
    TimedOut,
    NoTransaction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionPhase {
    AwaitingResponse,
    SegmentedResponse,
}

/// A confirmed request awaiting its response.
struct PendingTransaction {
    responder: oneshot::Sender<TsmResponse>,
    progress: watch::Sender<TransactionProgress>,
    owner: TransactionOwner,
    phase: TransactionPhase,
    /// Monotonic token used to reject a SegmentTimer expiry observed before
    /// newer segment activity acquired the TSM lock.
    segment_generation: u64,
    /// The service this request asked for. Clause 20.1.4.2 and 20.1.5.6 both
    /// require an acknowledgment's service-ack-choice to "contain the value of
    /// the BACnetConfirmedServiceChoice corresponding to the service contained
    /// in the previous BACnet-Confirmed-Service-Request that has resulted in
    /// this acknowledgment", so anything else is not this transaction's
    /// response.
    expected_service_choice: ConfirmedServiceChoice,
}

/// Transaction State Machine.
///
/// Tracks pending confirmed requests and correlates responses by
/// `(destination_mac, invoke_id)` and by the confirmed service each request
/// asked for.
pub struct Tsm {
    config: TsmConfig,
    allocators: HashMap<MacAddr, InvokeIdAllocator>,
    pending: HashMap<(MacAddr, u8), PendingTransaction>,
}

impl Tsm {
    pub fn new(config: TsmConfig) -> Self {
        Self {
            config,
            allocators: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    pub fn config(&self) -> &TsmConfig {
        &self.config
    }

    /// Allocate an invoke ID for the given destination MAC.
    /// Returns `None` if all 256 IDs are in use for this destination,
    /// or if the maximum number of tracked destinations has been reached.
    pub fn allocate_invoke_id(&mut self, destination_mac: &[u8]) -> Option<u8> {
        let key = MacAddr::from_slice(destination_mac);
        if !self.allocators.contains_key(&key) && self.allocators.len() >= MAX_TSM_DESTINATIONS {
            return None;
        }
        let allocator = self
            .allocators
            .entry(key)
            .or_insert_with(InvokeIdAllocator::new);
        allocator.allocate()
    }

    /// Release an invoke ID back to the pool for the given destination.
    /// Removes the allocator entry if all IDs are now free (prevents unbounded growth).
    pub fn release_invoke_id(&mut self, destination_mac: &[u8], invoke_id: u8) {
        let key = MacAddr::from_slice(destination_mac);
        if let Some(allocator) = self.allocators.get_mut(&key) {
            allocator.release(invoke_id);
            if allocator.all_free() {
                self.allocators.remove(&key);
            }
        }
    }

    /// Register a pending transaction. Returns a receiver that will deliver
    /// the response when it arrives.
    ///
    /// `service_choice` is the confirmed service being requested; a response
    /// labelled for any other service will not complete this transaction.
    pub fn register_transaction(
        &mut self,
        destination_mac: MacAddr,
        invoke_id: u8,
        service_choice: ConfirmedServiceChoice,
    ) -> oneshot::Receiver<TsmResponse> {
        self.register_transaction_with_progress(destination_mac, invoke_id, service_choice)
            .response
    }

    pub(crate) fn register_transaction_with_progress(
        &mut self,
        destination_mac: MacAddr,
        invoke_id: u8,
        service_choice: ConfirmedServiceChoice,
    ) -> TransactionRegistration {
        let (tx, rx) = oneshot::channel();
        let (progress_tx, progress_rx) = watch::channel(TransactionProgress::AwaitingResponse);
        let owner = TransactionOwner::new();
        debug_assert!(
            !self
                .pending
                .contains_key(&(destination_mac.clone(), invoke_id)),
            "duplicate TSM registration for invoke_id {}",
            invoke_id
        );
        self.pending.insert(
            (destination_mac, invoke_id),
            PendingTransaction {
                responder: tx,
                progress: progress_tx,
                owner: owner.clone(),
                phase: TransactionPhase::AwaitingResponse,
                segment_generation: 0,
                expected_service_choice: service_choice,
            },
        );
        TransactionRegistration {
            response: rx,
            progress: progress_rx,
            owner,
        }
    }

    /// Enter SEGMENTED_CONF after the first segment has been saved.
    ///
    /// The transition and RequestTimer retry authorization use the same TSM
    /// lock. Whichever changes or observes the phase first wins that decision;
    /// an authorized retry performs transport I/O only after releasing it.
    pub(crate) fn begin_segmented_response(
        &mut self,
        source_mac: &[u8],
        invoke_id: u8,
        owner: &TransactionOwner,
    ) -> Option<u64> {
        let key = (MacAddr::from_slice(source_mac), invoke_id);
        let pending = self.pending.get_mut(&key)?;
        if !pending.owner.same_as(owner) {
            return None;
        }
        pending.segment_generation = pending.segment_generation.wrapping_add(1);
        pending.phase = TransactionPhase::SegmentedResponse;
        let generation = pending.segment_generation;
        pending
            .progress
            .send_replace(TransactionProgress::SegmentedResponse { generation });
        Some(generation)
    }

    /// Restart SegmentTimer for a segment handled in SEGMENTED_CONF.
    pub(crate) fn record_segmented_response_activity(
        &mut self,
        source_mac: &[u8],
        invoke_id: u8,
        owner: &TransactionOwner,
    ) -> Option<u64> {
        let key = (MacAddr::from_slice(source_mac), invoke_id);
        let pending = self.pending.get_mut(&key)?;
        if !pending.owner.same_as(owner) || pending.phase != TransactionPhase::SegmentedResponse {
            return None;
        }
        pending.segment_generation = pending.segment_generation.wrapping_add(1);
        let generation = pending.segment_generation;
        pending
            .progress
            .send_replace(TransactionProgress::SegmentedResponse { generation });
        Some(generation)
    }

    /// Resume AWAIT_CONFIRMATION when a completed reassembly is not this
    /// transaction's response or cannot be delivered.
    pub(crate) fn reset_segmented_response(
        &mut self,
        source_mac: &[u8],
        invoke_id: u8,
        owner: &TransactionOwner,
    ) -> bool {
        let key = (MacAddr::from_slice(source_mac), invoke_id);
        let Some(pending) = self.pending.get_mut(&key) else {
            return false;
        };
        if !pending.owner.same_as(owner) || pending.phase != TransactionPhase::SegmentedResponse {
            return false;
        }
        pending.phase = TransactionPhase::AwaitingResponse;
        pending
            .progress
            .send_replace(TransactionProgress::AwaitingResponse);
        true
    }

    /// Arbitrate RequestTimer against the receive-side phase transition.
    ///
    /// Returning [`RequestTimerExpiration::Retry`] authorizes one retry. The
    /// caller then releases the enclosing TSM lock before transport I/O; a
    /// segmented-response transition that follows does not revoke that send.
    pub(crate) fn expire_request_timer(
        &mut self,
        destination_mac: &[u8],
        invoke_id: u8,
        owner: &TransactionOwner,
        final_timeout: bool,
    ) -> RequestTimerExpiration {
        let key = (MacAddr::from_slice(destination_mac), invoke_id);
        let Some(pending) = self.pending.get(&key) else {
            return RequestTimerExpiration::NoTransaction;
        };
        if !pending.owner.same_as(owner) {
            return RequestTimerExpiration::NoTransaction;
        }
        if pending.phase == TransactionPhase::SegmentedResponse {
            return RequestTimerExpiration::SegmentedResponse {
                generation: pending.segment_generation,
            };
        }
        if !final_timeout {
            return RequestTimerExpiration::Retry;
        }
        self.pending.remove(&key);
        self.release_invoke_id(destination_mac, invoke_id);
        RequestTimerExpiration::TimedOut
    }

    /// Cancel only if no segment activity has advanced past `generation`.
    pub(crate) fn expire_segment_timer(
        &mut self,
        destination_mac: &[u8],
        invoke_id: u8,
        owner: &TransactionOwner,
        generation: u64,
    ) -> SegmentTimerExpiration {
        let key = (MacAddr::from_slice(destination_mac), invoke_id);
        let Some(pending) = self.pending.get(&key) else {
            return SegmentTimerExpiration::NoTransaction;
        };
        if !pending.owner.same_as(owner) {
            return SegmentTimerExpiration::NoTransaction;
        }
        if pending.phase == TransactionPhase::AwaitingResponse {
            return SegmentTimerExpiration::AwaitingResponse;
        }
        if pending.segment_generation != generation {
            return SegmentTimerExpiration::Activity {
                generation: pending.segment_generation,
            };
        }
        self.pending.remove(&key);
        self.release_invoke_id(destination_mac, invoke_id);
        SegmentTimerExpiration::TimedOut
    }

    /// The confirmed service a pending transaction is waiting on, if any.
    ///
    /// Doubles as the "is a transaction pending" predicate: an inbound
    /// segmented response for an invoke ID nobody is waiting on should not be
    /// allocated a reassembly session.
    pub fn expected_service_choice(
        &self,
        source_mac: &[u8],
        invoke_id: u8,
    ) -> Option<ConfirmedServiceChoice> {
        let key = (MacAddr::from_slice(source_mac), invoke_id);
        self.pending.get(&key).map(|p| p.expected_service_choice)
    }

    pub(crate) fn owner_and_expected_service(
        &self,
        source_mac: &[u8],
        invoke_id: u8,
    ) -> Option<(TransactionOwner, ConfirmedServiceChoice)> {
        let key = (MacAddr::from_slice(source_mac), invoke_id);
        self.pending
            .get(&key)
            .map(|pending| (pending.owner.clone(), pending.expected_service_choice))
    }

    pub(crate) fn owner_is_current(
        &self,
        source_mac: &[u8],
        invoke_id: u8,
        owner: &TransactionOwner,
    ) -> bool {
        let key = (MacAddr::from_slice(source_mac), invoke_id);
        self.pending
            .get(&key)
            .is_some_and(|pending| pending.owner.same_as(owner))
    }

    /// Deliver a response to a pending transaction.
    ///
    /// `observed_service_choice` is the service the response claims to answer,
    /// or `None` for PDUs that carry no service choice at all — Reject and
    /// Abort (Clauses 20.1.8 and 20.1.9), which can only be correlated by
    /// invoke ID.
    ///
    /// A mismatch leaves the transaction pending and the invoke ID allocated.
    /// Completing it would hand the caller a payload belonging to a different
    /// service and free the ID for reuse while the real response is still in
    /// flight.
    pub fn complete_transaction(
        &mut self,
        source_mac: &[u8],
        invoke_id: u8,
        observed_service_choice: Option<ConfirmedServiceChoice>,
        response: TsmResponse,
    ) -> CompletionOutcome {
        self.complete_transaction_inner(
            source_mac,
            invoke_id,
            None,
            observed_service_choice,
            response,
        )
    }

    pub(crate) fn complete_transaction_for_owner(
        &mut self,
        source_mac: &[u8],
        invoke_id: u8,
        owner: &TransactionOwner,
        observed_service_choice: Option<ConfirmedServiceChoice>,
        response: TsmResponse,
    ) -> CompletionOutcome {
        self.complete_transaction_inner(
            source_mac,
            invoke_id,
            Some(owner),
            observed_service_choice,
            response,
        )
    }

    fn complete_transaction_inner(
        &mut self,
        source_mac: &[u8],
        invoke_id: u8,
        owner: Option<&TransactionOwner>,
        observed_service_choice: Option<ConfirmedServiceChoice>,
        response: TsmResponse,
    ) -> CompletionOutcome {
        let key = (MacAddr::from_slice(source_mac), invoke_id);
        let Entry::Occupied(entry) = self.pending.entry(key) else {
            return CompletionOutcome::NoTransaction;
        };
        if owner.is_some_and(|owner| !entry.get().owner.same_as(owner)) {
            return CompletionOutcome::NoTransaction;
        }
        let expected = entry.get().expected_service_choice;
        if let Some(observed) = observed_service_choice {
            if observed != expected {
                return CompletionOutcome::ServiceChoiceMismatch { expected, observed };
            }
        }
        // Taking the entry ends the borrow of `pending`, so the invoke ID can
        // be released without a second lookup that would have to be `expect`ed.
        let pending = entry.remove();
        self.release_invoke_id(source_mac, invoke_id);
        let _ = pending.responder.send(response);
        CompletionOutcome::Delivered
    }

    /// Cancel a pending transaction. Returns `true` if found.
    pub fn cancel_transaction(&mut self, destination_mac: &[u8], invoke_id: u8) -> bool {
        self.cancel_transaction_inner(destination_mac, invoke_id, None)
    }

    pub(crate) fn cancel_transaction_for_owner(
        &mut self,
        destination_mac: &[u8],
        invoke_id: u8,
        owner: &TransactionOwner,
    ) -> bool {
        self.cancel_transaction_inner(destination_mac, invoke_id, Some(owner))
    }

    fn cancel_transaction_inner(
        &mut self,
        destination_mac: &[u8],
        invoke_id: u8,
        owner: Option<&TransactionOwner>,
    ) -> bool {
        let key = (MacAddr::from_slice(destination_mac), invoke_id);
        if owner.is_some_and(|owner| {
            self.pending
                .get(&key)
                .is_none_or(|pending| !pending.owner.same_as(owner))
        }) {
            return false;
        }
        if self.pending.remove(&key).is_some() {
            self.release_invoke_id(destination_mac, invoke_id);
            true
        } else {
            false
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests;
