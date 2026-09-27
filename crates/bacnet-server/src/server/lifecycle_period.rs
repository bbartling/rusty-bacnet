use super::*;

/// Resolve the configured Event Enrollment interval into a tick period.
///
/// `tokio::time::interval` panics on a zero period, and that panic would land
/// inside a spawned task — `start` would still return `Ok` while enrollment
/// evaluation was silently dead. A configured `0` is clamped to one second
/// instead, matching how an invalid `vendor_id` is handled: warn loudly and
/// keep the device running. Use `enable_event_enrollment(false)` to actually
/// disable evaluation.
pub(in crate::server) fn event_enrollment_period(secs: u64) -> Duration {
    if secs == 0 {
        warn!(
            "event_enrollment_interval_secs is 0; clamping to 1s. \
             Use enable_event_enrollment(false) to disable Event Enrollment evaluation"
        );
        return Duration::from_secs(1);
    }
    Duration::from_secs(secs)
}

/// Install wall and monotonic clocks before the database becomes shared.
pub(super) fn install_database_clocks(
    db: &mut ObjectDatabase,
    clock_config: Option<ClockConfig>,
) -> (Option<Arc<ServerClock>>, tokio::time::Instant) {
    let clock = clock_config.map(|config| Arc::new(ServerClock::new(config)));
    let reader = clock
        .as_ref()
        .map(|clock| Arc::clone(clock) as Arc<dyn bacnet_objects::clock::ClockReader>);
    db.set_clock_reader(reader);
    let monotonic_origin = tokio::time::Instant::now();
    let monotonic_clock: Arc<bacnet_objects::traits::MonotonicClock> =
        Arc::new(move || tokio::time::Instant::now().saturating_duration_since(monotonic_origin));
    db.set_monotonic_clock_internal(Some(monotonic_clock));

    (clock, monotonic_origin)
}
