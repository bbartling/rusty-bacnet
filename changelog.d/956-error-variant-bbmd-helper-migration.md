---
section: Migration notes
commit: 5e9e6763b3224ff7dfc2e19ad7a6c9a132587a3a
---
- **Transport accessors (Rust API, #956):** add an
  `Error::UnsupportedTransport` arm to exhaustive matches. Read SC link state
  with `connection_state_changes()` instead of `ScTransport::connection()`,
  and MS/TP counts with `diagnostics()` instead of `node_state()`.
