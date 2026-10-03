---
section: Fixed
---
- **Rust API:** COV pairs the selected sample with validated Status_Flags, so
  a status-only change bypasses the numeric threshold, and `CovObservation`
  replaces the sample-only baseline (#817).
