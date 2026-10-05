---
section: Migration notes
---
- **Confirmed answers (Rust API, #1342):** `bacnet_server::server::CovAckResult`
  has a `Data(Bytes)` variant, the service data of a ComplexAck answering a
  read the server sent, and is no longer `Copy`; add an arm for it where you
  match the enum, and clone where you copied it.
