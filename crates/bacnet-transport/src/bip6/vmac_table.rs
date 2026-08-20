//! Deterministic BACnet/IPv6 VMAC and scoped-endpoint mappings.

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;

use super::Bip6Vmac;

/// Defensive cap for learned on-link VMAC mappings.
pub(super) const MAX_VMAC_TABLE_ENTRIES: usize = 4096;

/// VMAC-to-address mapping table per Clause U.5.
/// Updated from incoming frames and address-resolution exchanges.
#[derive(Debug, Clone)]
pub(super) struct VmacTable {
    mappings: Arc<tokio::sync::RwLock<VmacMappings>>,
}

#[derive(Debug, Default)]
struct VmacMappings {
    by_vmac: HashMap<Bip6Vmac, SocketAddrV6>,
    by_address: HashMap<(Ipv6Addr, u16), AddressMapping>,
}

#[derive(Debug, Clone, Copy)]
enum AddressMapping {
    Unique(Bip6Vmac, SocketAddrV6),
    /// The public 18-byte BACnet/IPv6 MAC omits the IPv6 scope ID, so the
    /// endpoint cannot be selected safely after the same address and port
    /// have been observed on more than one scoped interface.
    Ambiguous,
}

impl VmacTable {
    pub(super) fn new() -> Self {
        Self {
            mappings: Arc::new(tokio::sync::RwLock::new(VmacMappings::default())),
        }
    }

    /// Learn the latest VMAC and exact scoped endpoint from an incoming frame.
    pub(super) async fn learn(&self, vmac: Bip6Vmac, addr: SocketAddrV6) {
        let key = (*addr.ip(), addr.port());
        let mut mappings = self.mappings.write().await;

        let updates_known_vmac = mappings.by_vmac.contains_key(&vmac);
        let updates_known_address = mappings.by_address.contains_key(&key);
        if !updates_known_vmac
            && !updates_known_address
            && mappings.by_vmac.len() >= MAX_VMAC_TABLE_ENTRIES
        {
            return;
        }

        if let Some(old_addr) = mappings.by_vmac.get(&vmac).copied() {
            let old_key = (*old_addr.ip(), old_addr.port());
            if old_key != key
                && mappings
                    .by_address
                    .get(&old_key)
                    .is_some_and(
                        |mapping| matches!(mapping, AddressMapping::Unique(mapped_vmac, _) if *mapped_vmac == vmac),
                    )
            {
                mappings.by_address.remove(&old_key);
            }
        }

        match mappings.by_address.get(&key).copied() {
            Some(AddressMapping::Unique(_, old_addr)) if old_addr != addr => {
                mappings.by_address.insert(key, AddressMapping::Ambiguous);
                if updates_known_vmac || mappings.by_vmac.len() < MAX_VMAC_TABLE_ENTRIES {
                    mappings.by_vmac.insert(vmac, addr);
                }
                return;
            }
            Some(AddressMapping::Ambiguous) => {
                if updates_known_vmac || mappings.by_vmac.len() < MAX_VMAC_TABLE_ENTRIES {
                    mappings.by_vmac.insert(vmac, addr);
                }
                return;
            }
            Some(AddressMapping::Unique(old_vmac, _)) if old_vmac != vmac => {
                mappings.by_vmac.remove(&old_vmac);
            }
            _ => {}
        }

        mappings.by_vmac.insert(vmac, addr);
        mappings
            .by_address
            .insert(key, AddressMapping::Unique(vmac, addr));
    }

    /// Look up the B/IPv6 address for a VMAC.
    #[allow(dead_code)] // used by address-resolution handling and tests
    pub(super) async fn lookup(&self, vmac: &Bip6Vmac) -> Option<SocketAddrV6> {
        self.mappings.read().await.by_vmac.get(vmac).copied()
    }

    /// Resolve the public IPv6+port MAC to the latest VMAC and scoped endpoint.
    ///
    /// The 18-byte public MAC omits IPv6 scope ID. Returning the exact learned
    /// endpoint lets link-local replies preserve the ingress interface.
    pub(super) async fn resolve_by_addr(
        &self,
        ip: Ipv6Addr,
        port: u16,
    ) -> Option<(Bip6Vmac, SocketAddrV6)> {
        self.mappings
            .read()
            .await
            .by_address
            .get(&(ip, port))
            .and_then(|mapping| match mapping {
                AddressMapping::Unique(vmac, endpoint) => Some((*vmac, *endpoint)),
                AddressMapping::Ambiguous => None,
            })
    }

    #[cfg(test)]
    pub(super) async fn len(&self) -> usize {
        self.mappings.read().await.by_vmac.len()
    }
}
