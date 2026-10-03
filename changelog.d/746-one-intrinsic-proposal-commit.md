---
section: Changed
---
- **One intrinsic proposal/commit contract (Refs #746, pre-1.0 API break):**
  removed `BACnetObject::intrinsic_reporting_requires_atomic_commit` and the
  exported `impl_intrinsic_reporting!` macro. Custom objects implement the
  evaluate/tick proposal hooks and `commit_event_transition_internal` using the
  public commit types and their own state. Both server paths require commit
  success before notification distribution; unsupported or failed commits keep
  proposals retryable without consuming an event sequence number. Standalone
  detector `probe`/`tick` behavior is unchanged.
