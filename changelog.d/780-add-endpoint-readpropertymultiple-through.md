---
section: Fixed
---
- Add Rust/Python endpoint ReadPropertyMultiple through the shared read owner:
  1–64 explicit concrete references, ordered ACK correlation and per-occurrence
  value-free source READ records with one operation/recipient snapshot (#780).
  Source scope remains direct B/IP and Rust-configured; wider Audit stays #345.
  Pre-1.0 API change: RPM request encoding now returns Result and rejects empty
  object/property lists transactionally. All repository callers are migrated.
