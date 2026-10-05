---
section: Security
---
- **`EventNotificationCounters` (Rust API, Python):** one event notification is forwarded
  to at most 64 destinations across all Notification Forwarders, the rest counted in the new
  `forwarding_cap_dropped`, and a retransmitted ConfirmedEventNotification is not forwarded again
  (#1259).
