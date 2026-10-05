//! The retry loop every confirmed request this server sends shares: a
//! confirmed notification, or a request a run makes in another device.

use std::future::Future;

use tokio::sync::oneshot;
use tokio::time::Duration;

use super::{CommState, CovAckResult, NotificationOperation, NotificationWorkerResult, Rearm};

/// What one attempt at a confirmed request did.
pub(in crate::server) enum Attempt<W> {
    /// The request went out.
    Sent,
    /// The send failed. The attempt still waits for an answer, so it ends as
    /// silence would.
    NotSent,
    /// Nothing may be sent any more: the transaction ends at once, its invoke
    /// ID freed, with this reason. An answer that has already taken the lease
    /// is the exception: it is on its way, and it ends the transaction instead.
    Withdrawn(W),
}

/// How a confirmed request's attempts ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::server) enum AttemptsEnd {
    /// The device answered.
    Answered(CovAckResult),
    /// No attempt drew an answer.
    Exhausted,
    /// The adapter closed first.
    Closed,
}

impl From<AttemptsEnd> for NotificationWorkerResult {
    fn from(end: AttemptsEnd) -> Self {
        match end {
            // A notification sender only asks whether the device took the
            // request, and an answer with data says it did.
            AttemptsEnd::Answered(CovAckResult::Ack | CovAckResult::Data(_)) => Self::Ack,
            AttemptsEnd::Answered(CovAckResult::Error(refusal)) => Self::Error(refusal),
            AttemptsEnd::Exhausted => Self::Exhausted,
            AttemptsEnd::Closed => Self::Closed,
        }
    }
}

/// The shared retry loop for a notification none of whose attempts is
/// withdrawn: a send that fails waits out its timeout as silence would.
#[doc(hidden)]
pub async fn run_notification_worker<F, Fut, E>(
    operation: NotificationOperation,
    receiver: oneshot::Receiver<CovAckResult>,
    timeout: Duration,
    max_retries: u8,
    mut send: F,
) -> NotificationWorkerResult
where
    F: FnMut(u8) -> Fut,
    Fut: Future<Output = Result<(), E>>,
{
    let attempts = run_attempts(operation, receiver, timeout, max_retries, |attempt| {
        let sent = send(attempt);
        async move {
            match sent.await {
                Ok(()) => Attempt::<std::convert::Infallible>::Sent,
                Err(_) => Attempt::NotSent,
            }
        }
    });
    match attempts.await {
        Ok(end) => end.into(),
        Err(never) => match never {},
    }
}

/// DeviceCommunicationControl restricted initiation when a confirmed COV or
/// event notification was due for an attempt: it ended there, its invoke ID
/// freed, with nothing more sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) struct InitiationRestricted;

/// [`run_notification_worker`] for a confirmed COV or event notification,
/// which DeviceCommunicationControl stops (Clause 16.1). `comm_state` is read
/// before every attempt, the first and each retry: once DCC restricts
/// initiation the attempt is withdrawn instead of sent, so a notification
/// outstanding when it takes effect ends at its next retry.
pub(in crate::server) async fn run_notification_under_dcc<F, Fut, E>(
    operation: NotificationOperation,
    receiver: oneshot::Receiver<CovAckResult>,
    timeout: Duration,
    max_retries: u8,
    comm_state: &CommState,
    mut send: F,
) -> Result<NotificationWorkerResult, InitiationRestricted>
where
    F: FnMut(u8) -> Fut,
    Fut: Future<Output = Result<(), E>>,
{
    run_attempts(operation, receiver, timeout, max_retries, |attempt| {
        let sent = (!comm_state.initiation_restricted()).then(|| send(attempt));
        async move {
            let Some(sent) = sent else {
                return Attempt::Withdrawn(InitiationRestricted);
            };
            match sent.await {
                Ok(()) => Attempt::Sent,
                Err(_) => Attempt::NotSent,
            }
        }
    })
    .await
    .map(NotificationWorkerResult::from)
}

/// Make the first attempt and up to `max_retries` more, each waiting
/// `timeout` for the answer. Only silence earns another attempt; an attempt
/// that is withdrawn ends the transaction at once, unless an answer has
/// already taken the lease, which then ends it as usual.
pub(in crate::server) async fn run_attempts<F, Fut, W>(
    mut operation: NotificationOperation,
    mut receiver: oneshot::Receiver<CovAckResult>,
    timeout: Duration,
    max_retries: u8,
    mut attempt_with: F,
) -> Result<AttemptsEnd, W>
where
    F: FnMut(u8) -> Fut,
    Fut: Future<Output = Attempt<W>>,
{
    let mut attempt = 0;
    let answer = loop {
        let send_failed = match attempt_with(attempt).await {
            Attempt::Sent => false,
            Attempt::NotSent => true,
            Attempt::Withdrawn(reason) => {
                // The receiver was armed before this attempt was asked for,
                // so an answer that has taken the lease since, on another
                // thread, is on its way to it and still counts.
                if !operation.withdraw() {
                    break receiver.await;
                }
                operation.cancel();
                return Err(reason);
            }
        };
        // Borrowed, so an answer that claims the lease as the timer fires
        // still reaches this receiver.
        if let Ok(answer) = tokio::time::timeout(timeout, &mut receiver).await {
            break answer;
        }
        if attempt < max_retries {
            match operation.rearm() {
                Ok(next) => receiver = next,
                Err(Rearm::Claimed) => break receiver.await,
                Err(Rearm::Closed) => {
                    operation.cancel();
                    return Ok(AttemptsEnd::Closed);
                }
            }
            attempt += 1;
            continue;
        }
        if !operation.withdraw() {
            break receiver.await;
        }
        if send_failed {
            operation.cancel();
        } else {
            operation.release();
        }
        return Ok(AttemptsEnd::Exhausted);
    };
    Ok(match answer {
        Ok(answer) => {
            operation.terminal_completed();
            AttemptsEnd::Answered(answer)
        }
        // The sender went with the adapter's close.
        Err(_) => {
            operation.cancel();
            AttemptsEnd::Closed
        }
    })
}
