---
section: Changed
---
- **Breaking (Rust API):** `LogBufferRecords` requires `record_identity` and
  provides `record_position` and `timestamp_order`, which ReadRange now
  selects a log's records by (#1536).
