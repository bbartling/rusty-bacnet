//! Bounded endpoint send admission and explicit completion ownership.
use super::*;

pub(super) enum NetworkServicePayload {
    Apdu(Vec<u8>),
    LocalControl(Vec<u8>),
}

pub(super) struct NetworkServiceCommand {
    pub(super) payload: NetworkServicePayload,
    pub(super) destination: EndpointApduDestination,
    pub(super) expecting_reply: bool,
    pub(super) priority: NetworkPriority,
    pub(super) data_attributes: Vec<DataAttribute>,
    pub(super) completion: oneshot::Sender<EndpointSendOutcome>,
    pub(super) deadline: Option<tokio::time::Instant>,
    pub(super) cancel_on_drop: bool,
}

/// Completion of an admitted endpoint send, without claiming remote receipt.
#[doc(hidden)]
pub struct EndpointSendOutcome {
    /// Local send completion; success is not remote receipt or execution.
    pub result: Result<(), Error>,
    /// Transport execution began; an error may have an ambiguous wire outcome.
    pub attempted: bool,
}

/// One queued send completion. Deadline-bound and explicitly owned sends cancel
/// when this is dropped; ordinary deadline-free admission retains detached semantics.
#[doc(hidden)]
pub struct EndpointSend(oneshot::Receiver<EndpointSendOutcome>);

impl EndpointSend {
    #[doc(hidden)]
    pub async fn complete(self) -> EndpointSendOutcome {
        self.0.await.unwrap_or_else(|_| EndpointSendOutcome {
            result: Err(shutdown_error()),
            attempted: false,
        })
    }
}

/// Known local outcome before any endpoint transport execution.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointEgressAdmissionError {
    /// The bounded command queue has no free slot.
    QueueFull,
    /// The endpoint has sealed or its command receiver has closed.
    Closed,
}

impl From<EndpointEgressAdmissionError> for Error {
    fn from(error: EndpointEgressAdmissionError) -> Self {
        match error {
            EndpointEgressAdmissionError::QueueFull => {
                Error::Encoding("endpoint egress queue is full".into())
            }
            EndpointEgressAdmissionError::Closed => shutdown_error(),
        }
    }
}

/// Bounded APDU network-service sender for roles attached to an endpoint session.
#[doc(hidden)]
#[derive(Clone)]
pub struct EndpointEgress {
    pub(super) commands: mpsc::Sender<NetworkServiceCommand>,
    pub(super) open: Arc<AtomicBool>,
}

impl EndpointEgress {
    /// Whether this ingress still admits transport work.
    #[doc(hidden)]
    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire) && !self.commands.is_closed()
    }

    /// Sends one APDU without granting network lifecycle access.
    #[doc(hidden)]
    pub async fn send_apdu(
        &self,
        apdu: Vec<u8>,
        destination: EndpointApduDestination,
        expecting_reply: bool,
        priority: NetworkPriority,
        data_attributes: Vec<DataAttribute>,
    ) -> Result<(), Error> {
        self.admit_apdu(
            apdu,
            destination,
            expecting_reply,
            priority,
            data_attributes,
            None,
        )?
        .complete()
        .await
        .result
    }

    /// Queue one send synchronously, distinguishing admission from execution.
    /// A deadline also makes receiver cancellation retract queued work. Sends
    /// already in progress may have reached the peer when cancellation wins.
    #[doc(hidden)]
    pub fn admit_apdu(
        &self,
        apdu: Vec<u8>,
        destination: EndpointApduDestination,
        expecting_reply: bool,
        priority: NetworkPriority,
        data_attributes: Vec<DataAttribute>,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<EndpointSend, EndpointEgressAdmissionError> {
        self.admit(
            apdu,
            destination,
            expecting_reply,
            priority,
            data_attributes,
            deadline,
            deadline.is_some(),
        )
    }

    /// Queue caller-owned work without a deadline. Dropping its completion retracts
    /// queued work and cancels an in-progress transport future, whose wire outcome
    /// may already be ambiguous. A session-owned caller can retain this same guard.
    #[doc(hidden)]
    pub fn admit_owned_apdu(
        &self,
        apdu: Vec<u8>,
        destination: EndpointApduDestination,
        expecting_reply: bool,
        priority: NetworkPriority,
        data_attributes: Vec<DataAttribute>,
    ) -> Result<EndpointSend, EndpointEgressAdmissionError> {
        self.admit(
            apdu,
            destination,
            expecting_reply,
            priority,
            data_attributes,
            None,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn admit(
        &self,
        apdu: Vec<u8>,
        destination: EndpointApduDestination,
        expecting_reply: bool,
        priority: NetworkPriority,
        data_attributes: Vec<DataAttribute>,
        deadline: Option<tokio::time::Instant>,
        cancel_on_drop: bool,
    ) -> Result<EndpointSend, EndpointEgressAdmissionError> {
        if !self.open.load(Ordering::Acquire) {
            return Err(EndpointEgressAdmissionError::Closed);
        }
        let (completion, result) = oneshot::channel();
        let command = NetworkServiceCommand {
            payload: NetworkServicePayload::Apdu(apdu),
            destination,
            expecting_reply,
            priority,
            data_attributes,
            completion,
            deadline,
            cancel_on_drop,
        };
        match self.commands.try_send(command) {
            Ok(()) => Ok(EndpointSend(result)),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(EndpointEgressAdmissionError::Closed),
            Err(mpsc::error::TrySendError::Full(_)) => Err(EndpointEgressAdmissionError::QueueFull),
        }
    }

    /// Queue a local Network-Number-Is NPDU, with caller-owned cancellation.
    /// Dropping the waiter retracts queued work; a started send may have hit wire.
    #[doc(hidden)]
    pub async fn send_network_number_is(&self, npdu: Vec<u8>) -> Result<(), Error> {
        if npdu.len() != 6
            || npdu[..3] != [1, 0x80, 0x13]
            || npdu[5] > 1
            || matches!(u16::from_be_bytes([npdu[3], npdu[4]]), 0 | 65535)
        {
            return Err(Error::Encoding(
                "invalid local Network-Number-Is NPDU".into(),
            ));
        }
        if !self.is_open() {
            return Err(shutdown_error());
        }
        let (completion, result) = oneshot::channel();
        self.commands
            .try_send(NetworkServiceCommand {
                payload: NetworkServicePayload::LocalControl(npdu),
                destination: EndpointApduDestination::LocalBroadcast,
                expecting_reply: false,
                priority: NetworkPriority::NORMAL,
                data_attributes: Vec::new(),
                completion,
                deadline: None,
                cancel_on_drop: true,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Closed(_) => {
                    Error::from(EndpointEgressAdmissionError::Closed)
                }
                mpsc::error::TrySendError::Full(_) => {
                    Error::from(EndpointEgressAdmissionError::QueueFull)
                }
            })?;
        EndpointSend(result).complete().await.result
    }

    /// Wait for queue capacity without retaining an ordinary notification.
    /// This is a wake hint, not a reserved slot; callers retry synchronous admission.
    #[doc(hidden)]
    pub async fn wait_for_capacity(&self) -> Result<(), EndpointEgressAdmissionError> {
        if !self.open.load(Ordering::Acquire) {
            return Err(EndpointEgressAdmissionError::Closed);
        }
        let permit = self
            .commands
            .reserve()
            .await
            .map_err(|_| EndpointEgressAdmissionError::Closed)?;
        drop(permit);
        if self.open.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(EndpointEgressAdmissionError::Closed)
        }
    }

    /// Sends one direct unicast APDU without granting network lifecycle access.
    #[doc(hidden)]
    pub async fn send_direct(
        &self,
        apdu: Vec<u8>,
        destination_mac: MacAddr,
        expecting_reply: bool,
        priority: NetworkPriority,
    ) -> Result<(), Error> {
        self.send_apdu(
            apdu,
            EndpointApduDestination::Direct { destination_mac },
            expecting_reply,
            priority,
            Vec::new(),
        )
        .await
    }
}
