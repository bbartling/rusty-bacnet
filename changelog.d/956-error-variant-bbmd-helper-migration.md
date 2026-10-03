---
section: Migration notes
---
- **Transport accessors (Rust API, #956):** add an
  `Error::UnsupportedTransport` arm to exhaustive matches. Read SC link state
  with `connection_state_changes()` instead of `ScTransport::connection()`,
  and MS/TP counts with `diagnostics()` instead of `node_state()`.
