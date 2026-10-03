---
section: Changed
---
- **Target Device Audit recipient (Refs #728, pre-1.0 API break):** recipient state
  moves from `AuditReporterConfig.recipient` into the built-in Device. Python uses
  `configure_audit_recipient` instead of the removed `recipient_device_instance`
  keyword. The installed target profile exposes a required/writable recipient;
  direct/local/WP/WPM changes atomically admit mandatory old/new notifications.
  Active Device/Reporter membership is protected through shutdown quiescence.
  `ObjectDatabase::remove` and `with_object_adapter` now return `Result` to report
  protection denial. The raw mutable Device hook becomes an operation capability.
  See the [bounded contract](docs/device-audit-recipient.md); broader Audit
  conformance remains open.
