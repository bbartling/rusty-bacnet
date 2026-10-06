//! The one clock the server's rate limiters and coalescing windows read
//! (#1548, #1550): discovery, time synchronization, the DCC disable budget
//! and the received-event-log allowances.

use std::time::Instant;

/// Now, on tokio's clock.
///
/// In production this is exactly `Instant::now()`: only tokio's `test-util`
/// feature can pause the clock, and it is a dev-dependency, so a release
/// build reads the system's monotonic clock with or without a runtime. Under
/// `#[tokio::test(start_paused = true)]` it reads the paused clock, so a test
/// steps every window with `tokio::time::advance` and a runner stall can't
/// move one.
///
/// A limiter takes every instant it stores or compares from here, never from
/// `Instant::now()` directly: under a paused clock the two differ, and a
/// window measured between them would be wrong.
pub(crate) fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}
