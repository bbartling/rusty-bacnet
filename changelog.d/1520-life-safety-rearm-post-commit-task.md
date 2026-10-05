---
section: Fixed
---
- **Breaking (Rust API):** `set_life_safety_operation_expected_local` must run inside a Tokio runtime,
  failing and changing nothing outside one; once Operation_Expected changes, its COV notifications go
  out even if the caller is dropped (#1520).
