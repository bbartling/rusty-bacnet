---
section: Migration notes
---
- **COV table (Rust API, #810, #817, #826, #833, #840):**
  `CovSubscription::last_notified_observation`, a `CovObservation`, replaces
  the float `last_notified_value` baseline, and `set_last_notified_value` is
  gone.
