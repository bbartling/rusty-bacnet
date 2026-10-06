---
section: Migration notes
---
- **Log buffers (Rust API, #1536):** a custom `LogBufferRecords` implements
  `record_identity(index)`, the identity `log_record_identities_internal`
  lists at that index, and overrides `record_position` and `timestamp_order`
  when it can answer them without walking its records. A custom
  `AuditLogStorage` keeps its sequence numbers consecutive from the oldest
  record.
