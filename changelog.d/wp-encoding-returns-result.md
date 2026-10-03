---
section: Changed
---
- Pre-1.0 WP encoding now returns `Result` and rejects priorities outside 1–16
  transactionally. Direct/routed clients reject before lookup/admission/traffic;
  Python direct, device-based, and multi-device WP validate synchronously, with
  complete batch validation before dispatch. NULL and inbound error behavior stay
  unchanged; WPM is a separate API.
