---
section: Migration notes
---
- **Answer matching (Rust API, #1465):** `CanonicalPeer::from_source` takes the
  known local network number as a third argument (`None` keeps the old
  matching). `NotificationTransactions::admit_terminal`,
  `bacnet_endpoint::roles::admit_once` and `inbound_canonical_peer` take it
  too. `ServerRoleHandle::admit_notification_terminal` is removed; admit
  through the session, or `admit_from_source` on the coordinator.
