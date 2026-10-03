---
section: Changed
---
- **Breaking (Rust and Python API):** AuditLogQuery's success filter is the
  three-state `BACnetSuccessFilter`, so failures-only now filters, and the
  start sequence number is an Unsigned64 cursor (#345).
