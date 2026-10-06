---
section: Added
---
- **Rust API:** `read_log_page` on the client and endpoint client pages a
  log's records from the oldest, a sequence number, a position or a time,
  across the sequence wrap, reporting gaps and returning a checkpoint cursor;
  a device whose pages stop advancing fails with `Error::LogNotAdvancing`
  (#1530).
