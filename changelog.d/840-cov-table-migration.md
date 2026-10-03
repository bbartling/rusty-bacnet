---
section: Migration notes
---
- **COV table (Rust API, #810, #817, #826, #833, #840):** use `CovRecipient`
  for `MultipleRecipient` and `CovPeerKey`, with `recipient()` and
  `CovPolicy::reserved_recipients` for `peer_key()` and `reserved_peer_keys`.
  `CovObservation` and `set_last_notified_observation` replace the float
  baseline, and `subscribe_multiple` takes the route.
