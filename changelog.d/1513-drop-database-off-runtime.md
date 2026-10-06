---
section: Added
---
- **Rust API:** `bacnet_server::server::drop_database_off_runtime` lets go of
  a handle on the object database, dropping it on Tokio's blocking pool when
  it is the last, so durable objects' final saves don't hold a runtime worker
  (#1513).
