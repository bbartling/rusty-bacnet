---
section: Changed
---
- **Rust and Python API:** `AuditLogObject::new` and Python `add_audit_log` reopen
  a log with the Buffer_Size it stored, which a peer may have written, instead of
  failing when `buffer_size` differs; a warning names both sizes (#1238).
