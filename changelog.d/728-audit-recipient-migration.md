---
section: Migration notes
---
- **Audit recipient (#728):** provision the recipient on the built-in Device
  instead of `AuditReporterConfig.recipient` or `StaticSourceAuditRecipient`,
  and set route facts with `source_audit_device_binding`. Python calls
  `configure_audit_recipient` instead of passing `recipient_device_instance`.
  `ObjectDatabase::remove` and `with_object_adapter` return `Result`.
