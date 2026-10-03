---
section: Changed
---
- **Standalone Python direct B/IP Audit Log parent forwarding (RB-23b, Refs #345):**
  `BACnetServer.add_device_binding(device_instance, address)` reuses the existing
  address parser but accepts only `transport="bip"` servers and six-byte B/IP
  addresses (IPv4 host:port or equivalent hex). Other server transports, incompatible
  address shapes and duplicate Device bindings are rejected without retention.
  The broader parser grammar remains available elsewhere, not for these bindings. Pre-start
  `configure_audit_log_parent(instance, *, parent_device_instance, parent_audit_log_instance)`
  sets the registered log's `Member_Of`; valid calls replace the prior parent,
  invalid/missing/duplicate local identities do not mutate it. Both settings freeze
  at startup ownership transfer. Installed-extension loopback tests prove child
  receipt, parent forwarding/query and durable reopen without deleting child records.
  The existing confirmed one-attempt Rust forwarding and RB-23a sink policies are
  unchanged. Reapply configuration on a new server after reopen. See
  [Python parent forwarding](docs/python-api.md#direct-audit-log-parent-forwarding).
  No IPv6/SC/MS/TP forwarding, routed binding API, active Python Reporter,
  retry/outbox/queue, full Audit/BIBB, BTL/certification or #345 closure is claimed.
  This supersedes the RB-23a forwarding
  exclusion only for the documented direct B/IP-parent subset.
