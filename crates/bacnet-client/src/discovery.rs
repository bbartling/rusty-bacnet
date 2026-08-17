//! Device discovery table — collects IAm responses for WhoIs/WhoHas lookups.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bacnet_types::enums::Segmentation;
use bacnet_types::primitives::ObjectIdentifier;
use bacnet_types::MacAddr;

/// Information about a discovered BACnet device.
#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    /// The device's object identifier (always ObjectType::DEVICE).
    pub object_identifier: ObjectIdentifier,
    /// The MAC address from which the IAm was received.
    pub mac_address: MacAddr,
    /// Maximum APDU length the device accepts.
    pub max_apdu_length: u32,
    /// Segmentation support level.
    pub segmentation_supported: Segmentation,
    /// Maximum segments the remote device accepts (None = unlimited/unspecified).
    pub max_segments_accepted: Option<u32>,
    /// Vendor identifier.
    pub vendor_id: u16,
    /// When this entry was last updated.
    pub last_seen: Instant,
    /// If this device is behind a router, the BACnet network number it resides on.
    pub source_network: Option<u16>,
    /// If this device is behind a router, its MAC address on the remote network.
    pub source_address: Option<MacAddr>,
}

/// Thread-safe device discovery table.
///
/// Keyed by device instance number (the instance part of the DEVICE object
/// identifier). Updated whenever an IAm is received.
#[derive(Debug, Default)]
pub struct DeviceTable {
    devices: HashMap<u32, DiscoveredDevice>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeviceUpsertResult {
    Inserted,
    Updated,
    Dropped,
}

impl DeviceTable {
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
        }
    }

    /// Insert or update a discovered device.
    ///
    /// The table is capped at 4096 entries. If the table is full and the
    /// device is not already present, the new entry is silently dropped.
    pub fn upsert(&mut self, device: DiscoveredDevice) {
        let _ = self.upsert_with_result(device);
    }

    pub(crate) fn upsert_with_result(&mut self, device: DiscoveredDevice) -> DeviceUpsertResult {
        const MAX_DEVICE_TABLE_ENTRIES: usize = 4096;
        let key = device.object_identifier.instance_number();
        let is_existing = self.devices.contains_key(&key);
        if !is_existing && self.devices.len() >= MAX_DEVICE_TABLE_ENTRIES {
            return DeviceUpsertResult::Dropped;
        }
        self.devices.insert(key, device);
        if is_existing {
            DeviceUpsertResult::Updated
        } else {
            DeviceUpsertResult::Inserted
        }
    }

    /// Get all discovered devices as a snapshot.
    pub fn all(&self) -> Vec<DiscoveredDevice> {
        self.devices.values().cloned().collect()
    }

    /// Look up a device by instance number.
    pub fn get(&self, instance: u32) -> Option<&DiscoveredDevice> {
        self.devices.get(&instance)
    }

    /// Look up a device by its MAC address.
    pub fn get_by_mac(&self, mac: &[u8]) -> Option<&DiscoveredDevice> {
        self.devices
            .values()
            .find(|d| d.mac_address.as_slice() == mac)
    }

    /// Look up a routed device by its remote network number and MAC address.
    ///
    /// A routed device's `mac_address` holds the router it was heard through,
    /// which every device behind that router shares; its own identity is the
    /// SNET/SADR of the NPDU that carried its I-Am, stored as
    /// `source_network` and `source_address`.
    ///
    /// The table is keyed by device instance, so two rows can share one
    /// SNET/SADR (a re-commissioned instance survives until the stale purge).
    /// The freshest `last_seen` wins: it holds what the device most recently
    /// advertised.
    pub fn get_by_network_address(
        &self,
        network: u16,
        address: &[u8],
    ) -> Option<&DiscoveredDevice> {
        self.devices
            .values()
            .filter(|d| {
                d.source_network == Some(network)
                    && d.source_address
                        .as_ref()
                        .is_some_and(|a| a.as_slice() == address)
            })
            .max_by_key(|d| d.last_seen)
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.devices.clear();
    }

    /// Number of discovered devices.
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Remove entries whose `last_seen` is older than `max_age`.
    pub fn purge_stale(&mut self, max_age: Duration) {
        let _ = self.purge_stale_at(Instant::now(), max_age);
    }

    pub(crate) fn purge_stale_collect(&mut self, max_age: Duration) -> Vec<DiscoveredDevice> {
        self.purge_stale_at(Instant::now(), max_age)
    }

    fn purge_stale_at(&mut self, now: Instant, max_age: Duration) -> Vec<DiscoveredDevice> {
        let stale_keys: Vec<u32> = self
            .devices
            .iter()
            .filter_map(|(key, device)| {
                let is_stale = now
                    .checked_duration_since(device.last_seen)
                    .is_some_and(|age| age > max_age);
                is_stale.then_some(*key)
            })
            .collect();

        stale_keys
            .into_iter()
            .filter_map(|key| self.devices.remove(&key))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bacnet_types::enums::ObjectType;

    fn make_device(instance: u32) -> DiscoveredDevice {
        DiscoveredDevice {
            object_identifier: ObjectIdentifier::new(ObjectType::DEVICE, instance).unwrap(),
            mac_address: MacAddr::from_slice(&[192, 168, 1, 100, 0xBA, 0xC0]),
            max_apdu_length: 1476,
            segmentation_supported: Segmentation::NONE,
            max_segments_accepted: None,
            vendor_id: 42,
            last_seen: Instant::now(),
            source_network: None,
            source_address: None,
        }
    }

    #[test]
    fn upsert_and_get() {
        let mut table = DeviceTable::new();
        table.upsert(make_device(1234));
        assert_eq!(table.len(), 1);
        let dev = table.get(1234).unwrap();
        assert_eq!(dev.vendor_id, 42);
    }

    #[test]
    fn upsert_updates_existing() {
        let mut table = DeviceTable::new();
        table.upsert(make_device(1234));
        let mut updated = make_device(1234);
        updated.vendor_id = 99;
        table.upsert(updated);
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(1234).unwrap().vendor_id, 99);
    }

    #[test]
    fn upsert_with_result_reports_insert_and_update() {
        let mut table = DeviceTable::new();
        assert_eq!(
            table.upsert_with_result(make_device(1234)),
            DeviceUpsertResult::Inserted
        );
        assert_eq!(
            table.upsert_with_result(make_device(1234)),
            DeviceUpsertResult::Updated
        );
    }

    #[test]
    fn all_returns_snapshot() {
        let mut table = DeviceTable::new();
        table.upsert(make_device(1));
        table.upsert(make_device(2));
        table.upsert(make_device(3));
        assert_eq!(table.all().len(), 3);
    }

    #[test]
    fn clear_empties_table() {
        let mut table = DeviceTable::new();
        table.upsert(make_device(1));
        table.clear();
        assert!(table.is_empty());
    }

    #[test]
    fn get_by_mac_finds_device() {
        let mut table = DeviceTable::new();
        table.upsert(make_device(1234));
        let mac = &[192, 168, 1, 100, 0xBA, 0xC0];
        let dev = table.get_by_mac(mac).unwrap();
        assert_eq!(dev.object_identifier.instance_number(), 1234);
    }

    #[test]
    fn get_by_mac_not_found() {
        let mut table = DeviceTable::new();
        table.upsert(make_device(1234));
        assert!(table.get_by_mac(&[10, 0, 0, 1, 0xBA, 0xC0]).is_none());
    }

    fn make_routed_device(instance: u32, network: u16, address: &[u8]) -> DiscoveredDevice {
        let mut device = make_device(instance);
        device.source_network = Some(network);
        device.source_address = Some(MacAddr::from_slice(address));
        device
    }

    #[test]
    fn get_by_network_address_finds_routed_device() {
        let mut table = DeviceTable::new();
        table.upsert(make_routed_device(1, 100, &[0x03]));
        table.upsert(make_routed_device(2, 200, &[0x03]));
        let dev = table.get_by_network_address(200, &[0x03]).unwrap();
        assert_eq!(dev.object_identifier.instance_number(), 2);
    }

    /// A local device whose MAC happens to equal the queried remote address
    /// lives in a different address space and must not match.
    #[test]
    fn get_by_network_address_ignores_local_devices() {
        let mut table = DeviceTable::new();
        let mut local = make_device(1);
        local.mac_address = MacAddr::from_slice(&[0x03]);
        table.upsert(local);
        assert!(table.get_by_network_address(100, &[0x03]).is_none());
    }

    #[test]
    fn get_by_network_address_requires_both_terms() {
        let mut table = DeviceTable::new();
        table.upsert(make_routed_device(1, 100, &[0x03]));
        assert!(table.get_by_network_address(100, &[0x04]).is_none());
        assert!(table.get_by_network_address(101, &[0x03]).is_none());
    }

    /// A re-commissioned device instance leaves two rows at one SNET/SADR
    /// until the stale purge; the freshest advertisement must win, not an
    /// arbitrary hash-order pick.
    #[test]
    fn get_by_network_address_prefers_freshest_entry() {
        let mut table = DeviceTable::new();
        let now = Instant::now();
        let mut stale = make_routed_device(1, 100, &[0x03]);
        stale.max_apdu_length = 1476;
        stale.last_seen = now;
        let mut fresh = make_routed_device(2, 100, &[0x03]);
        fresh.max_apdu_length = 128;
        fresh.last_seen = now + Duration::from_secs(60);
        table.upsert(stale);
        table.upsert(fresh);

        let dev = table.get_by_network_address(100, &[0x03]).unwrap();
        assert_eq!(dev.object_identifier.instance_number(), 2);
        assert_eq!(dev.max_apdu_length, 128);
    }

    #[test]
    fn purge_stale_removes_old_entries() {
        let mut table = DeviceTable::new();
        let now = Instant::now();
        let mut old_device = make_device(1);
        old_device.last_seen = now;
        table.upsert(old_device);
        let mut fresh_device = make_device(2);
        fresh_device.last_seen = now + Duration::from_secs(120);
        table.upsert(fresh_device);
        assert_eq!(table.len(), 2);

        let removed = table.purge_stale_at(now + Duration::from_secs(120), Duration::from_secs(60));
        assert_eq!(table.len(), 1);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].object_identifier.instance_number(), 1);
        assert!(table.get(1).is_none());
        assert!(table.get(2).is_some());
    }

    #[test]
    fn purge_stale_keeps_all_when_fresh() {
        let mut table = DeviceTable::new();
        table.upsert(make_device(1));
        table.upsert(make_device(2));
        table.purge_stale(Duration::from_secs(60));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn purge_stale_removes_all_when_expired() {
        let mut table = DeviceTable::new();
        let now = Instant::now();
        let mut d1 = make_device(1);
        d1.last_seen = now;
        let mut d2 = make_device(2);
        d2.last_seen = now;
        table.upsert(d1);
        table.upsert(d2);
        let removed = table.purge_stale_at(now + Duration::from_secs(200), Duration::from_secs(60));
        assert!(table.is_empty());
        assert_eq!(removed.len(), 2);
    }

    #[test]
    fn upsert_refreshes_last_seen() {
        let mut table = DeviceTable::new();
        let now = Instant::now();
        let mut old_device = make_device(1);
        old_device.last_seen = now;
        table.upsert(old_device);

        let mut refreshed = make_device(1);
        refreshed.last_seen = now + Duration::from_secs(120);
        table.upsert(refreshed);
        let removed = table.purge_stale_at(now + Duration::from_secs(120), Duration::from_secs(60));
        assert_eq!(table.len(), 1);
        assert!(removed.is_empty());
        assert!(table.get(1).is_some());
    }

    #[test]
    fn purge_stale_handles_max_age_larger_than_instant_history() {
        let mut table = DeviceTable::new();
        table.upsert(make_device(1));

        table.purge_stale(Duration::MAX);

        assert_eq!(table.len(), 1);
    }
}
