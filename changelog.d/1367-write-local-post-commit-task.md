---
section: Fixed
---
- **Breaking (Rust API):** local writes (`write_local`, `set_present_value_local` and the like) must
  run inside a Tokio runtime, failing and writing nothing outside one; once committed, their COV, event,
  Schedule and Staging work finishes even if the caller is dropped (#1367).
