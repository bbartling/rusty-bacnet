//! The probe table on its own (#1322): joins, the hold-off, the cap, sends
//! that move the deadline, withdrawals and answers. The clock is paused.
use super::*;

const WAIT: Duration = Duration::from_secs(3);

fn device(instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::DEVICE, instance).unwrap()
}

/// Start a probe for `device` at `now`, which must be new.
fn start(probes: &mut BindingProbes, device: ObjectIdentifier, now: TokioInstant) -> ProbeWait {
    match probes.begin(device, now, WAIT) {
        ProbeStep::Send(wait) => wait,
        step => panic!("a new probe, not {step:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn a_probe_is_joined_while_out_then_holds_off_its_device_for_a_minute() {
    let mut probes = BindingProbes::default();
    let begun = TokioInstant::now();
    let first = start(&mut probes, device(9), begun);
    // The Who-Is goes out a second after the probe starts; the wait and the
    // hold-off count from there.
    let sent = begun + Duration::from_secs(1);
    probes.sent(&device(9), first.id(), sent, WAIT);
    let joined = sent + WAIT - Duration::from_millis(1);
    assert!(matches!(
        probes.begin(device(9), joined, WAIT),
        ProbeStep::Join(_)
    ));
    // Another device has its own probe.
    start(&mut probes, device(10), joined);
    for held in [
        sent + WAIT,
        sent + WHO_IS_HOLD_OFF - Duration::from_millis(1),
    ] {
        assert!(matches!(
            probes.begin(device(9), held, WAIT),
            ProbeStep::HeldOff
        ));
    }
    start(&mut probes, device(9), sent + WHO_IS_HOLD_OFF);
}

#[tokio::test(start_paused = true)]
async fn the_send_moves_the_deadline_every_waiting_write_shares() {
    let mut probes = BindingProbes::default();
    let begun = TokioInstant::now();
    let first = start(&mut probes, device(9), begun);
    let ProbeStep::Join(second) = probes.begin(device(9), begun, WAIT) else {
        panic!("the probe joined");
    };
    let id = first.id();
    let waits = tokio::spawn(async move { (first.answered().await, second.answered().await) });
    tokio::time::advance(Duration::from_secs(1)).await;
    probes.sent(&device(9), id, TokioInstant::now(), WAIT);
    assert_eq!(waits.await.unwrap(), (false, false));
    assert_eq!(TokioInstant::now(), begun + Duration::from_secs(1) + WAIT);
}

#[tokio::test(start_paused = true)]
async fn an_answer_wakes_every_wait_and_frees_the_device() {
    let mut probes = BindingProbes::default();
    let begun = TokioInstant::now();
    let first = start(&mut probes, device(9), begun);
    let ProbeStep::Join(second) = probes.begin(device(9), begun, WAIT) else {
        panic!("the probe joined");
    };
    probes.answer(&device(9));
    assert!(first.answered().await);
    assert!(second.answered().await);
    assert_eq!(TokioInstant::now(), begun);
    assert_eq!(probes.len(), 0);
    // An answer for a device with no probe changes nothing.
    probes.answer(&device(11));
    let unanswered = start(&mut probes, device(9), begun);
    assert!(!unanswered.answered().await);
    assert_eq!(TokioInstant::now(), begun + WAIT);
}

#[tokio::test(start_paused = true)]
async fn a_withdrawn_probe_ends_its_waits_and_holds_nothing_off() {
    let mut probes = BindingProbes::default();
    let begun = TokioInstant::now();
    let first = start(&mut probes, device(9), begun);
    let ProbeStep::Join(second) = probes.begin(device(9), begun, WAIT) else {
        panic!("the probe joined");
    };
    let id = first.id();
    // Another probe's ID leaves this one alone.
    probes.withdraw(&device(9), id.wrapping_add(1));
    assert_eq!(probes.len(), 1);
    probes.withdraw(&device(9), id);
    assert!(!first.answered().await);
    assert!(!second.answered().await);
    assert_eq!(TokioInstant::now(), begun);
    let next = start(&mut probes, device(9), begun);
    assert_ne!(next.id(), id);
    // A send or a withdrawal naming the old probe doesn't touch the new one.
    probes.sent(&device(9), id, begun + WHO_IS_HOLD_OFF, WAIT);
    probes.withdraw(&device(9), id);
    assert!(matches!(
        probes.begin(device(9), begun + WAIT, WAIT),
        ProbeStep::HeldOff
    ));
}

#[tokio::test(start_paused = true)]
async fn probes_are_capped_until_their_hold_off_ends() {
    let mut probes = BindingProbes::default();
    let begun = TokioInstant::now();
    for instance in 0..u32::try_from(MAX_PROBES).unwrap() {
        start(&mut probes, device(instance), begun);
    }
    let extra = device(5_000);
    let late = begun + WHO_IS_HOLD_OFF - Duration::from_millis(1);
    assert!(matches!(probes.begin(extra, late, WAIT), ProbeStep::Full));
    assert_eq!(probes.len(), MAX_PROBES);
    // An answered device frees its place at once.
    probes.answer(&device(0));
    start(&mut probes, extra, late);
    assert!(matches!(
        probes.begin(device(5_001), late, WAIT),
        ProbeStep::Full
    ));
    // Once the others' hold-off ends, they make room.
    start(&mut probes, device(5_001), begun + WHO_IS_HOLD_OFF);
    assert_eq!(probes.len(), 2);
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

#[test]
fn a_remote_scope_on_this_network_by_number_is_local() {
    assert_eq!(WhoIsScope::Remote(7).localize(Some(7)), WhoIsScope::Local);
    for (scope, local) in [
        (WhoIsScope::Remote(5), Some(7)),
        (WhoIsScope::Remote(7), None),
        (WhoIsScope::Global, Some(7)),
        (WhoIsScope::Local, Some(7)),
    ] {
        assert_eq!(scope.localize(local), scope);
    }
}
