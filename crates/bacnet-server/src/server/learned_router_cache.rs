//! Bounded next-hop learning, separate from confirmed transaction ownership.

use std::collections::HashMap;

use bacnet_types::MacAddr;

/// A full cache leaves additional networks using routed local broadcast.
const MAX_LEARNED_ROUTERS: usize = 64;

/// Router MACs learned from admitted terminal responses for remote networks.
/// The notification owner decides admission before this cache is updated.
pub(super) struct LearnedRouterCache {
    routers: HashMap<u16, MacAddr>,
}

impl LearnedRouterCache {
    pub(super) fn new() -> Self {
        Self {
            routers: HashMap::new(),
        }
    }

    /// Update an existing DNET even when the cache cannot admit new networks.
    pub(super) fn learn_router(&mut self, network: u16, router: &MacAddr) {
        if router.is_empty() {
            return;
        }
        if self.routers.len() >= MAX_LEARNED_ROUTERS && !self.routers.contains_key(&network) {
            return;
        }
        self.routers.insert(network, router.clone());
    }

    pub(super) fn cached_router(&self, network: u16) -> Option<MacAddr> {
        self.routers.get(&network).cloned()
    }
}
