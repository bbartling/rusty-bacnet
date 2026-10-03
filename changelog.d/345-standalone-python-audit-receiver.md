---
section: Changed
---
- **Standalone Python Audit receiver/query parity (RB-23a, Refs #345):**
  `BACnetServer.configure_audit_notification_sink(instance, *, policy)` selects
  one registered file-backed Audit Log before startup. Explicit `allow_all` admits
  confirmed and unconfirmed notifications through the existing Rust receiver;
  unconfigured servers and `deny_all` remain fail-closed. Static admission never
  calls Python or treats payload identities as verified origin. Configuration
  validation preserves pending registrations. Typed queries read committed records
  after reopen; existing receipt, no-response and error semantics remain unchanged.
  Existing callers require no migration; enabling receipt is opt-in after
  `add_audit_log()`. See [Python receiver configuration](docs/python-api.md#inbound-audit-notification-sink).
  No active Python Reporter, parent forwarding, shared-endpoint producer, full
  Audit/BIBB/BTL support or #345 closure is claimed.
