---
section: Added
---
- **Tracked router control receiver (#1242):**
  `RouterOptions::network_control_receiver_with_admission` returns the
  router's network-control receiver as an `AdmissionReceiver`, whose counters
  report its queue depth, high-water mark and drops.
