//! Targeted Who-Is probes for devices a remote write has no fresh binding
//! for (#1322).
//!
//! A Command action or Channel member in another device is addressed from
//! the device bindings. When the device has none, or only an I-Am older than
//! the binding lifetime, the write asks for it: one Who-Is whose low and high
//! limits are both the device's instance (Clause 16.10), then a bounded wait
//! for the I-Am. The I-Am lands in the binding table like any other and wakes
//! every write waiting on the probe; with none by the deadline, they fail.
//!
//! Where the Who-Is goes is a [`WhoIsScope`]: the network the device's last
//! I-Am came from while the table still holds that stale observation, or the
//! whole internetwork for a device it has never heard from. A write whose
//! probe drew nothing drops the stale observation, so the device's next
//! Who-Is goes global rather than to the old network again.
//!
//! The probes bound that traffic. A device gets at most one Who-Is per
//! [`WHO_IS_HOLD_OFF`]: a write that misses while a probe is out waits on
//! that probe, and one that misses after the probe drew nothing fails at
//! once. At most [`MAX_PROBES`] devices are tracked at a time. A device that
//! answers frees its place at once and then stays bound for the binding
//! lifetime, so the cap limits the Who-Is requests that go unanswered: at
//! most that many per hold-off. A write that would need one more fails
//! unsent.
//!
//! A probe's wait and hold-off count from when its Who-Is went out: the
//! write that starts it records the send ([`BindingProbes::sent`]), which
//! moves the deadline every waiting write shares. Until then both count from
//! the probe's start, so a write cancelled before it sends still leaves a
//! bounded probe.
//!
//! The probes live inside the binding table, under its lock, so finding no
//! binding and starting a probe are one step an I-Am can't fall between.

use super::*;
use tokio::time::Instant as TokioInstant;

/// The least time between two Who-Is requests for one device.
pub(super) const WHO_IS_HOLD_OFF: Duration = Duration::from_secs(60);

/// The most devices with a probe out or held off at once.
pub(super) const MAX_PROBES: usize = 256;

/// Stands in for a wait too long to add to an instant: about 30 years.
const FAR_FUTURE: Duration = Duration::from_secs(86_400 * 365 * 30);

/// Where a targeted Who-Is goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WhoIsScope {
    /// A broadcast on this network.
    Local,
    /// A broadcast on this remote network (DNET with no DADR).
    Remote(u16),
    /// A broadcast on every network (DNET 65535).
    Global,
}

impl WhoIsScope {
    /// A remote network numbered `local_network`, the one this device is
    /// attached to, is this network: the Who-Is goes with no DNET, as
    /// `RecipientRoute::localize` sends event recipients there (#1365). A
    /// non-routing device drops an NPDU whose DNET names its own network.
    pub(super) fn localize(self, local_network: Option<u16>) -> Self {
        match self {
            Self::Remote(network) if Some(network) == local_network => Self::Local,
            scope => scope,
        }
    }
}

/// What the writes waiting on a probe watch.
#[derive(Debug, Clone, Copy)]
struct ProbeState {
    /// When they give up.
    deadline: TokioInstant,
    /// Whether the device's I-Am was heard.
    answered: bool,
}

/// One device's Who-Is.
#[derive(Debug)]
struct Probe {
    /// Tells this probe from a later one for the same device.
    id: u64,
    /// When the Who-Is went out, or the probe started until it does.
    sent: TokioInstant,
    /// When the writes waiting on it give up.
    deadline: TokioInstant,
    state: watch::Sender<ProbeState>,
}

impl Probe {
    fn wait(&self) -> ProbeWait {
        ProbeWait {
            id: self.id,
            state: self.state.subscribe(),
        }
    }

    /// Whether the probe still holds back another Who-Is for its device.
    fn holds_at(&self, now: TokioInstant) -> bool {
        now < self.deadline || now < self.sent + WHO_IS_HOLD_OFF
    }
}

/// What a write with no fresh binding for a device does next.
#[derive(Debug)]
pub(super) enum ProbeStep {
    /// Send the Who-Is, then wait on it.
    Send(ProbeWait),
    /// A Who-Is for the device is out already: wait on that one.
    Join(ProbeWait),
    /// A Who-Is for the device went out within the hold-off and drew no
    /// I-Am in time.
    HeldOff,
    /// [`MAX_PROBES`] other devices are being probed.
    Full,
}

/// A write's wait on a probe.
#[derive(Debug)]
pub(super) struct ProbeWait {
    id: u64,
    state: watch::Receiver<ProbeState>,
}

impl ProbeWait {
    /// The probe this waits on, for [`BindingProbes::sent`] and
    /// [`BindingProbes::withdraw`].
    pub(super) fn id(&self) -> u64 {
        self.id
    }

    /// Wait for the device's I-Am until the probe's deadline, following the
    /// deadline as the send moves it, and say whether the I-Am came. A probe
    /// withdrawn before its Who-Is went out ends the wait at once.
    pub(super) async fn answered(mut self) -> bool {
        loop {
            let ProbeState { deadline, answered } = *self.state.borrow_and_update();
            if answered {
                return true;
            }
            match tokio::time::timeout_at(deadline, self.state.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return self.state.borrow().answered,
                Err(_) => return false,
            }
        }
    }
}

/// The devices with a Who-Is out or held off.
#[derive(Debug, Default)]
pub(super) struct BindingProbes {
    probes: HashMap<ObjectIdentifier, Probe>,
    next_id: u64,
}

impl BindingProbes {
    /// Join `device`'s probe, or start one whose writes wait `wait` from
    /// `now`, unless the hold-off or the cap stops it. The caller sends the
    /// Who-Is for [`ProbeStep::Send`], then reports it with [`Self::sent`].
    pub(super) fn begin(
        &mut self,
        device: ObjectIdentifier,
        now: TokioInstant,
        wait: Duration,
    ) -> ProbeStep {
        if let Some(probe) = self.probes.get(&device) {
            if now < probe.deadline {
                return ProbeStep::Join(probe.wait());
            }
            if probe.holds_at(now) {
                return ProbeStep::HeldOff;
            }
        }
        self.probes.retain(|_, probe| probe.holds_at(now));
        if self.probes.len() >= MAX_PROBES {
            return ProbeStep::Full;
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let deadline = after(now, wait);
        let (state, _) = watch::channel(ProbeState {
            deadline,
            answered: false,
        });
        let probe = Probe {
            id,
            sent: now,
            deadline,
            state,
        };
        let wait = probe.wait();
        self.probes.insert(device, probe);
        ProbeStep::Send(wait)
    }

    /// The Who-Is of `device`'s probe `id` went out at `now`: its wait of
    /// `wait` and its hold-off count from here.
    pub(super) fn sent(
        &mut self,
        device: &ObjectIdentifier,
        id: u64,
        now: TokioInstant,
        wait: Duration,
    ) {
        if let Some(probe) = self.probes.get_mut(device).filter(|probe| probe.id == id) {
            probe.sent = now;
            probe.deadline = after(now, wait);
            let deadline = probe.deadline;
            probe.state.send_modify(|state| state.deadline = deadline);
        }
    }

    /// Drop `device`'s probe `id`, whose Who-Is never went out: the writes
    /// waiting on it stop at once, and the device isn't held off.
    pub(super) fn withdraw(&mut self, device: &ObjectIdentifier, id: u64) {
        if self.probes.get(device).is_some_and(|probe| probe.id == id) {
            self.probes.remove(device);
        }
    }

    /// `device`'s I-Am was heard: wake the writes waiting on its probe and
    /// drop it, since the device is bound again.
    pub(super) fn answer(&mut self, device: &ObjectIdentifier) {
        if let Some(probe) = self.probes.remove(device) {
            probe.state.send_modify(|state| state.answered = true);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.probes.len()
    }
}

/// `wait` after `now`, or far in the future for a wait too long to add.
fn after(now: TokioInstant, wait: Duration) -> TokioInstant {
    now.checked_add(wait).unwrap_or(now + FAR_FUTURE)
}

#[cfg(test)]
#[path = "binding_probes_tests.rs"]
mod tests;
