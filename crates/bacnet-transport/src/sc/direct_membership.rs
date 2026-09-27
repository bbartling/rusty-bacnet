//! Node-switch identity ownership across accepted and initiated direct peers.
//!
//! Reservations protect both identities while Accept is in flight. No network
//! I/O runs under this lock. Only commit retires an incumbent; dropping an
//! uncommitted reservation is rollback. Generations never repeat in this process.
use crate::sc_frame::Vmac;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use tokio::sync::watch;

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
type Uuid = [u8; 16];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectRole {
    Accepted,
    Outbound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    DuplicateVmac,
    Resources,
    Busy,
}

struct Entry {
    generation: u64,
    uuid: Uuid,
    vmac: Vmac,
    role: DirectRole,
    retired: watch::Sender<bool>,
}

#[derive(Default)]
struct State {
    established: HashMap<u64, Entry>,
    reserved: HashMap<u64, Entry>,
}

#[derive(Default)]
pub(crate) struct DirectMembership {
    state: Mutex<State>,
}

impl DirectMembership {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reserve(
        self: &Arc<Self>,
        uuid: Uuid,
        vmac: Vmac,
        local_uuid: Uuid,
        local_vmac: Vmac,
        role: DirectRole,
        cap: usize,
    ) -> Result<Reservation, Refusal> {
        let mut state = self.state.lock().unwrap();
        if uuid == local_uuid
            || vmac == local_vmac
            || state
                .established
                .values()
                .chain(state.reserved.values())
                .any(|e| e.vmac == vmac && e.uuid != uuid)
        {
            return Err(Refusal::DuplicateVmac);
        }
        // A competing attempt for either identity waits by retrying a later
        // connection; bounded admission never queues unlimited reservations.
        if state
            .reserved
            .values()
            .any(|e| e.uuid == uuid || e.vmac == vmac)
        {
            return Err(Refusal::Busy);
        }
        // Count the union by UUID, including reservations replacing an entry
        // which can disappear before commit. Replacing the other role consumes
        // a new slot; that role's quota cannot subsidize this one.
        let mut peers = std::collections::HashSet::new();
        for e in state.established.values().chain(state.reserved.values()) {
            if e.role == role {
                peers.insert(e.uuid);
            }
        }
        peers.insert(uuid);
        if peers.len() > cap {
            return Err(Refusal::Resources);
        }
        let generation = NEXT_GENERATION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Refusal::Resources)?;
        let (retired, _) = watch::channel(false);
        state.reserved.insert(
            generation,
            Entry {
                generation,
                uuid,
                vmac,
                role,
                retired,
            },
        );
        Ok(Reservation {
            owner: Arc::clone(self),
            generation,
        })
    }

    #[cfg(test)]
    pub(crate) fn current_generations(&self) -> Vec<u64> {
        self.state
            .lock()
            .unwrap()
            .established
            .keys()
            .copied()
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn counts(&self) -> (usize, usize) {
        let state = self.state.lock().unwrap();
        (
            state
                .established
                .values()
                .filter(|e| e.role == DirectRole::Accepted)
                .count(),
            state.reserved.len(),
        )
    }
}

pub(crate) struct Reservation {
    owner: Arc<DirectMembership>,
    generation: u64,
}

impl Reservation {
    pub(crate) fn commit(self) -> Arc<Membership> {
        let mut state = self.owner.state.lock().unwrap();
        let entry = state
            .reserved
            .remove(&self.generation)
            .expect("owned reservation");
        let previous = state
            .established
            .values()
            .find(|e| e.uuid == entry.uuid)
            .map(|e| e.generation);
        if let Some(previous) = previous {
            let old = state.established.remove(&previous).unwrap();
            old.retired.send_replace(true);
        }
        let member = Arc::new(Membership {
            owner: Arc::clone(&self.owner),
            generation: self.generation,
            vmac: entry.vmac,
            retired: entry.retired.clone(),
        });
        state.established.insert(self.generation, entry);
        drop(state);
        member
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.owner
            .state
            .lock()
            .unwrap()
            .reserved
            .remove(&self.generation);
    }
}

pub(crate) struct Membership {
    owner: Arc<DirectMembership>,
    pub(crate) generation: u64,
    pub(crate) vmac: Vmac,
    retired: watch::Sender<bool>,
}

impl Membership {
    pub(crate) fn retirement(&self) -> watch::Receiver<bool> {
        self.retired.subscribe()
    }
    pub(crate) fn is_current(&self) -> bool {
        self.with_current(|| ()).is_some()
    }
    // Admission and replacement have one linearization point. The callback
    // must be synchronous, bounded and must not re-enter this registry.
    pub(crate) fn with_current<T>(&self, f: impl FnOnce() -> T) -> Option<T> {
        let state = self.owner.state.lock().unwrap();
        state.established.contains_key(&self.generation).then(f)
    }
    pub(crate) fn retire(&self) {
        self.owner
            .state
            .lock()
            .unwrap()
            .established
            .remove(&self.generation);
        self.retired.send_replace(true);
    }
}
impl Drop for Membership {
    fn drop(&mut self) {
        self.retire();
    }
}

pub(crate) fn disconnect_request() -> crate::sc_frame::ScMessage {
    crate::sc_frame::ScMessage {
        function: crate::sc_frame::ScFunction::DisconnectRequest,
        message_id: 0,
        originating_vmac: None,
        destination_vmac: None,
        dest_options: Vec::new(),
        data_options: Vec::new(),
        payload: bytes::Bytes::new(),
    }
}
