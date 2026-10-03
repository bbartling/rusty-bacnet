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
//! The probes bound that traffic. A device gets at most one Who-Is per
//! [`WHO_IS_HOLD_OFF`], counted from when it went out: a write that misses
//! while a probe is out waits on that probe, and one that misses after the
//! probe drew nothing fails at once. At most [`MAX_PROBES`] devices are
//! tracked at a time, which also caps the server's Who-Is traffic at that
//! many per hold-off; a write that would need one more fails unsent.
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

/// One device's Who-Is.
#[derive(Debug)]
struct Probe {
    /// When it went out.
    sent: TokioInstant,
    /// When the writes waiting on it give up.
    deadline: TokioInstant,
    /// Turns true when the device's I-Am is heard.
    answered: watch::Sender<bool>,
}

impl Probe {
    fn wait(&self) -> ProbeWait {
        ProbeWait {
            deadline: self.deadline,
            answered: self.answered.subscribe(),
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
    deadline: TokioInstant,
    answered: watch::Receiver<bool>,
}

impl ProbeWait {
    /// Wait for the device's I-Am until the probe's deadline, and say whether
    /// it came.
    pub(super) async fn answered(mut self) -> bool {
        let heard = self.answered.wait_for(|answered| *answered);
        matches!(
            tokio::time::timeout_at(self.deadline, heard).await,
            Ok(Ok(_))
        )
    }
}

/// The devices with a Who-Is out or held off.
#[derive(Debug, Default)]
pub(super) struct BindingProbes {
    probes: HashMap<ObjectIdentifier, Probe>,
}

impl BindingProbes {
    /// Join `device`'s probe, or start one whose writes wait `wait` from
    /// `now`, unless the hold-off or the cap stops it. The caller sends the
    /// Who-Is for [`ProbeStep::Send`].
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
        let (answered, _) = watch::channel(false);
        let probe = Probe {
            sent: now,
            deadline: now.checked_add(wait).unwrap_or(now + FAR_FUTURE),
            answered,
        };
        let wait = probe.wait();
        self.probes.insert(device, probe);
        ProbeStep::Send(wait)
    }

    /// `device`'s I-Am was heard: wake the writes waiting on its probe and
    /// drop it, since the device is bound again.
    pub(super) fn answer(&mut self, device: &ObjectIdentifier) {
        if let Some(probe) = self.probes.remove(device) {
            probe.answered.send_replace(true);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.probes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WAIT: Duration = Duration::from_secs(3);

    fn device(instance: u32) -> ObjectIdentifier {
        ObjectIdentifier::new(ObjectType::DEVICE, instance).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn a_probe_is_joined_while_out_then_holds_off_its_device_for_a_minute() {
        let mut probes = BindingProbes::default();
        let start = TokioInstant::now();
        assert!(matches!(
            probes.begin(device(9), start, WAIT),
            ProbeStep::Send(_)
        ));
        let joined = start + WAIT - Duration::from_millis(1);
        assert!(matches!(
            probes.begin(device(9), joined, WAIT),
            ProbeStep::Join(_)
        ));
        // Another device has its own probe.
        assert!(matches!(
            probes.begin(device(10), joined, WAIT),
            ProbeStep::Send(_)
        ));
        for held in [start + WAIT, start + WHO_IS_HOLD_OFF - Duration::from_millis(1)] {
            assert!(matches!(
                probes.begin(device(9), held, WAIT),
                ProbeStep::HeldOff
            ));
        }
        assert!(matches!(
            probes.begin(device(9), start + WHO_IS_HOLD_OFF, WAIT),
            ProbeStep::Send(_)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_wakes_every_wait_and_frees_the_device() {
        let mut probes = BindingProbes::default();
        let start = TokioInstant::now();
        let ProbeStep::Send(first) = probes.begin(device(9), start, WAIT) else {
            panic!("a new probe");
        };
        let ProbeStep::Join(second) = probes.begin(device(9), start, WAIT) else {
            panic!("the probe joined");
        };
        probes.answer(&device(9));
        assert!(first.answered().await);
        assert!(second.answered().await);
        assert_eq!(TokioInstant::now(), start);
        assert_eq!(probes.len(), 0);
        // An answer for a device with no probe changes nothing.
        probes.answer(&device(11));
        let ProbeStep::Send(unanswered) = probes.begin(device(9), start, WAIT) else {
            panic!("a new probe once answered");
        };
        assert!(!unanswered.answered().await);
        assert_eq!(TokioInstant::now(), start + WAIT);
    }

    #[tokio::test(start_paused = true)]
    async fn probes_are_capped_until_their_hold_off_ends() {
        let mut probes = BindingProbes::default();
        let start = TokioInstant::now();
        for instance in 0..u32::try_from(MAX_PROBES).unwrap() {
            assert!(matches!(
                probes.begin(device(instance), start, WAIT),
                ProbeStep::Send(_)
            ));
        }
        let extra = device(5_000);
        let late = start + WHO_IS_HOLD_OFF - Duration::from_millis(1);
        assert!(matches!(probes.begin(extra, late, WAIT), ProbeStep::Full));
        assert_eq!(probes.len(), MAX_PROBES);
        // Once the others' hold-off ends, they make room.
        let after = start + WHO_IS_HOLD_OFF;
        assert!(matches!(
            probes.begin(extra, after, WAIT),
            ProbeStep::Send(_)
        ));
        assert_eq!(probes.len(), 1);
    }

    #[test]
    fn a_wait_too_long_to_add_still_starts_a_probe() {
        let mut probes = BindingProbes::default();
        let now = TokioInstant::now();
        assert!(matches!(
            probes.begin(device(9), now, Duration::MAX),
            ProbeStep::Send(_)
        ));
        assert!(matches!(
            probes.begin(device(9), now + WHO_IS_HOLD_OFF, Duration::MAX),
            ProbeStep::Join(_)
        ));
    }
}
