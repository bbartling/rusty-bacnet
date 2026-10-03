---
section: Migration notes
---
- **Intrinsic reporting (Rust API, #746):** custom objects implement the
  evaluate and tick proposal hooks and `commit_event_transition_internal`
  instead of using `impl_intrinsic_reporting!` and
  `intrinsic_reporting_requires_atomic_commit`.
