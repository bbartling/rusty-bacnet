//! Heap placement for large startup futures (#953).
//!
//! An unoptimized build gives each future an async fn awaits or spawns at
//! least one stack slot sized to the whole future, in that function's poll
//! frame, and tokio's spawn path copies a task's future through several more
//! frames. Server startup awaited and spawned futures of 3 to 16 KB this way,
//! which cost a debug-build `build()` 50 to 100 KiB of stack. These helpers
//! create such a future in a frame of their own, which returns before polling
//! starts, and keep it on the heap. They are for one-time startup work and
//! long-lived tasks, never a per-request path.

use std::future::Future;
use std::pin::Pin;

use tokio::task::JoinHandle;

/// Create the future `make` returns and move it to the heap.
///
/// Awaiting the box costs the caller a pointer where awaiting the future
/// itself would cost the whole future, in the caller's state and poll frame.
pub(super) fn boxed<F: Future>(make: impl FnOnce() -> F) -> Pin<Box<F>> {
    Box::pin(make())
}

/// Spawn the future `make` returns with the task's future on the heap, so the
/// spawn path moves a pointer.
pub(super) fn spawn_boxed<F>(make: impl FnOnce() -> F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(boxed(make))
}
