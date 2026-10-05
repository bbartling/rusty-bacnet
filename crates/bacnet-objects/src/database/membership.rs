//! Work a change of the database's membership leaves for the server (#1341).
//!
//! Adding, replacing or removing an object can change others: a Pulse
//! Converter whose Input_Reference names it is judged again
//! (`input_references.rs`), and its Reliability can change with the verdict.
//! The database makes that change at once, under the caller's exclusive
//! access, but COV is the server's, so the database queues the objects that
//! changed and calls the waker the server installed. The server takes the
//! queue under its next database guard and fans COV out for it: at once
//! after a CreateObject or DeleteObject, and from a background task after an
//! application's own `add` or `remove`.
//!
//! The queue holds each object once. Without a server nothing takes it, so
//! it stays bounded by the objects that can change this way.

use std::sync::Arc;

use bacnet_types::primitives::ObjectIdentifier;

use super::ObjectDatabase;

/// Called when a change of membership queues work, so a server can take it
/// (`ObjectDatabase::take_membership_work_internal`). It runs under the
/// caller's exclusive access to the database, so it must not wait for that
/// access itself.
#[doc(hidden)]
pub type MembershipWaker = dyn Fn() + Send + Sync;

/// The queue behind [`MembershipWork`], and the waker to call when it grows.
#[derive(Default)]
pub(super) struct MembershipQueue {
    changed: Vec<ObjectIdentifier>,
    waker: Option<Arc<MembershipWaker>>,
}

/// What changes of membership left for the server since it last took them.
#[doc(hidden)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MembershipWork {
    /// Objects whose readable state the changes altered, each owing COV:
    /// Pulse Converters whose Reliability the check of their Input_Reference
    /// changed.
    pub changed: Vec<ObjectIdentifier>,
}

impl MembershipWork {
    /// Whether there is nothing to do.
    pub fn is_empty(&self) -> bool {
        self.changed.is_empty()
    }
}

impl ObjectDatabase {
    /// Install the callback a change of membership that queues work calls,
    /// or remove it with `None`. The bundled server installs one at start.
    #[doc(hidden)]
    pub fn set_membership_waker_internal(&mut self, waker: Option<Arc<MembershipWaker>>) {
        self.membership.waker = waker;
    }

    /// Take the work changes of membership queued since the last call.
    #[doc(hidden)]
    pub fn take_membership_work_internal(&mut self) -> MembershipWork {
        MembershipWork {
            changed: std::mem::take(&mut self.membership.changed),
        }
    }

    /// Do what adding, replacing or removing `oid` asks of the other
    /// objects, and queue what the server owes for it. The object added is
    /// judged too, but owes nothing: it starts from what it holds.
    pub(super) fn membership_changed(&mut self, oid: ObjectIdentifier) {
        let mut changed = self.recheck_input_references(oid);
        changed.retain(|converter| *converter != oid);
        if changed.is_empty() {
            return;
        }
        for oid in changed {
            if !self.membership.changed.contains(&oid) {
                self.membership.changed.push(oid);
            }
        }
        if let Some(waker) = &self.membership.waker {
            waker();
        }
    }
}
