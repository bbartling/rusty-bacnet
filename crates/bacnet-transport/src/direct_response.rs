//! A bounded response capability for one verified direct connection.
use crate::port::DirectScIdentity;
use crate::sc::direct_membership::Membership;
use crate::sc_frame::{encode_sc_message, ScFunction, ScMessage};
use bacnet_types::error::Error;
use bytes::{Bytes, BytesMut};
use std::sync::{
    atomic::{AtomicBool, AtomicU16, Ordering},
    Arc, Weak,
};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

#[cfg(test)]
pub(crate) const RESPONSE_QUEUE_CAPACITY: usize = crate::sc::direct_egress::WRITE_CAPACITY;
pub(crate) use crate::sc::direct_egress::DirectWrite as ResponseWrite;

/// Lifetime of direct response writes owned by one network/server instance.
///
/// Seal synchronously at shutdown. Queued writes keep only a weak reference and
/// cannot start after observing the seal or owner drop. Already-started bounded
/// writes cannot be recalled. This owns no connection or identity registration.
#[derive(Debug, Default)]
pub struct DirectResponseScope(Arc<AtomicBool>);

impl DirectResponseScope {
    /// Reject new and queued direct responses. Idempotent and irreversible.
    pub fn seal(&self) {
        self.0.store(true, Ordering::Release);
    }
}

impl Drop for DirectResponseScope {
    fn drop(&mut self) {
        self.seal();
    }
}

/// Sealed authority to reply only on the original verified direct-SC socket.
///
/// Clones share the socket's bounded ordinary/reply queue; they own neither the
/// socket nor its membership.
/// Retirement, close, a full queue or a bounded write failure returns an error.
/// There is no address lookup, replacement/Hub fallback or redial. Success is a
/// local write result, not proof of peer receipt. Already-started writes cannot
/// be rolled back. This capability is distinct from authorization provenance.
///
/// ```compile_fail
/// use bacnet_transport::port::DirectResponse;
/// let forged = DirectResponse { };
/// ```
#[derive(Clone)]
pub struct DirectResponse {
    member: Weak<Membership>,
    identity: DirectScIdentity,
    send: mpsc::Sender<ResponseWrite>,
    next_message: Arc<AtomicU16>,
    peer_max_bvlc: u16,
    peer_max_npdu: u16,
    wait: Duration,
}

impl std::fmt::Debug for DirectResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectResponse").finish_non_exhaustive()
    }
}

impl DirectResponse {
    #[cfg(any(test, feature = "sc-tls"))]
    pub(crate) fn new(member: &Arc<Membership>, identity: DirectScIdentity) -> Self {
        Self {
            member: Arc::downgrade(member),
            identity,
            send: member.egress.send.clone(),
            next_message: member.egress.next_message.clone(),
            peer_max_bvlc: member.egress.limits.0,
            peer_max_npdu: member.egress.limits.1,
            wait: member.egress.wait,
        }
    }

    /// Immutable peer/incarnation associated with this exact writer.
    pub fn identity(&self) -> DirectScIdentity {
        self.identity
    }

    /// Maximum response NPDU payload after the original peer's independent
    /// NPDU and complete BVLC receive limits. This immutable sizing snapshot
    /// does not check liveness or confer authority to send after retirement.
    pub fn max_npdu_length(&self) -> usize {
        usize::from(self.peer_max_npdu)
            .min(usize::from(self.peer_max_bvlc).saturating_sub(Self::encode_frame(&[], 0).len()))
    }

    fn encode_frame(npdu: &[u8], message_id: u16) -> BytesMut {
        let frame = ScMessage {
            function: ScFunction::EncapsulatedNpdu,
            message_id,
            originating_vmac: None,
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::copy_from_slice(npdu),
        };
        let mut bytes = BytesMut::new();
        encode_sc_message(&mut bytes, &frame);
        bytes
    }

    /// Send one encoded response NPDU without Data Options on this connection.
    /// The peer's negotiated NPDU and complete BVLC limits are both enforced.
    pub async fn send(&self, npdu: &[u8], scope: &DirectResponseScope) -> Result<(), Error> {
        if scope.0.load(Ordering::Acquire) {
            return Err(unavailable());
        }
        if npdu.len() > usize::from(self.peer_max_npdu) {
            return Err(Error::Encoding(
                "direct response exceeds peer Max-NPDU-Length".into(),
            ));
        }
        let bytes = Self::encode_frame(npdu, self.next_message.fetch_add(1, Ordering::Relaxed));
        if bytes.len() > usize::from(self.peer_max_bvlc) {
            return Err(Error::Encoding(
                "direct response exceeds peer Max-BVLC-Length".into(),
            ));
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(self.wait)
            .ok_or_else(unavailable)?;
        let (done, recv) = oneshot::channel();
        // The temporary strong membership is dropped before awaiting. Saved
        // request/replay contexts must never keep a dead socket registered.
        self.member
            .upgrade()
            .and_then(|member| {
                member.with_current(|| {
                    self.send.try_send(ResponseWrite {
                        bytes: bytes.freeze(),
                        done,
                        scope: Some(Arc::downgrade(&scope.0)),
                        started: Arc::new(AtomicBool::new(false)),
                        deadline,
                    })
                })
            })
            .ok_or_else(unavailable)?
            .map_err(|_| unavailable())?;
        tokio::time::timeout(self.wait, recv)
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?
    }
}

pub(crate) fn unavailable() -> Error {
    Error::Transport(std::io::Error::new(
        std::io::ErrorKind::NotConnected,
        "original direct response connection unavailable",
    ))
}

#[cfg(test)]
#[path = "direct_response_tests.rs"]
mod tests;
