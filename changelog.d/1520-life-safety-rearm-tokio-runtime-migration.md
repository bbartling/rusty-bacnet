---
section: Migration notes
---
- **Life Safety rearm (Rust API, #1520):** await `set_life_safety_operation_expected_local` inside a
  Tokio runtime, as the other local writes already require. Polled by another executor, it now fails
  with `Error::Encoding` before anything changes.
