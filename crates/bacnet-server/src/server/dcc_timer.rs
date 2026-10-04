use super::*;

#[path = "comm_state.rs"]
mod comm_state;
pub(crate) use comm_state::CommState;
pub use comm_state::DccState;

/// Last-owner destruction aborts the timer even if server Drop could not acquire
/// the async slot while a request was replacing it.
#[derive(Default)]
pub(crate) struct TimerSlot(pub(crate) Option<JoinHandle<()>>);
impl std::ops::Deref for TimerSlot {
    type Target = Option<JoinHandle<()>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for TimerSlot {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for TimerSlot {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}

// Borrow the handle in its owning slot through the join. Cancelling the caller
// leaves the (possibly already aborted) handle available for the next cleanup.
pub(super) async fn cancel(slot: &mut Option<JoinHandle<()>>) {
    if let Some(task) = slot.as_mut() {
        task.abort();
        let _ = task.await;
    }
    *slot = None;
}

/// One DeviceCommunicationControl request and where it came from.
pub(super) struct DccRequest<'a> {
    pub(super) service_data: &'a [u8],
    pub(super) source_mac: &'a [u8],
    pub(super) source: Option<&'a bacnet_encoding::npdu::NpduAddress>,
}

/// Apply a DCC request and own its revert timer. Whenever communication is
/// enabled again, by the request or when the timer expires, `cov_resume` is
/// rearmed so timestamped COV changes held meanwhile go out promptly (#856).
pub(super) async fn replace(
    timer: &Arc<Mutex<crate::server::dcc_timer::TimerSlot>>,
    comm_state: &Arc<CommState>,
    request: DccRequest<'_>,
    config: &ServerConfig,
    request_tasks: &super::request_tasks::RequestTaskSpawner,
    cov_resume: &crate::cov::timed::TimedStore,
) -> Result<dcc_outcomes::DccMetadata, handlers::device_mgmt::DccFailure> {
    let DccRequest {
        service_data,
        source_mac,
        source,
    } = request;
    // Decode and validate once, retaining only non-secret proposed state and
    // metadata. Never change live state before a cancellable await.
    let (proposed, duration) =
        handlers::device_mgmt::validate_dcc(service_data, &config.dcc_password, config.dcc_policy)?;
    let mode = bacnet_types::enums::EnableDisable::from(proposed).to_raw();
    // Short-circuit source refusal before touching the shared budget. ENABLE
    // never checks it. A successful charge precedes every cancellable await.
    if config
        .dcc_source_restriction
        .as_ref()
        .is_some_and(|restriction| {
            config.dcc_policy != DccPolicy::RequirePassword
                || !restriction.allows(source_mac, source)
        })
        || (proposed == DccState::DisableInitiation && !request_tasks.admit_dcc_disable())
    {
        return Err(handlers::device_mgmt::DccFailure {
            error: Error::Protocol {
                class: ErrorClass::SERVICES.to_raw() as u32,
                code: ErrorCode::SERVICE_REQUEST_DENIED.to_raw() as u32,
            },
            outcome: dcc_outcomes::DccOutcome::PolicyDenied,
            metadata: dcc_outcomes::DccMetadata {
                mode: Some(mode),
                duration,
            },
        });
    }
    let mut slot = timer.lock().await;
    cancel(&mut slot).await;
    // Replacement, expiry, and shutdown share this linearization boundary.
    // No suspension between the live commit and installing the new owner.
    comm_state.set(proposed);
    if proposed == DccState::Enable {
        cov_resume.rearm();
    }
    if let Some(minutes) = duration {
        let owner = Arc::downgrade(timer);
        let comm = Arc::clone(comm_state);
        let cov_resume = cov_resume.clone();
        **slot = Some(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(minutes as u64 * 60)).await;
            if let Some(owner) = owner.upgrade() {
                // An old task waiting here can be aborted and joined while a
                // replacement holds the slot; it never joins or removes itself.
                let _slot = owner.lock().await;
                comm.set(DccState::Enable);
                cov_resume.rearm();
                debug!(
                    "DCC timer expired after {} min, state reverted to ENABLE",
                    minutes
                );
            }
        }));
    }
    Ok(dcc_outcomes::DccMetadata {
        mode: Some(mode),
        duration,
    })
}
