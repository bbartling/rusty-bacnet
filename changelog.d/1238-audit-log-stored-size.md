---
section: Changed
---
- **Rust API:** `AuditLogObject::new` reopens a log with the Buffer_Size it
  stored, which a peer may have written, instead of failing when `buffer_size`
  differs (#1238).
