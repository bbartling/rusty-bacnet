---
section: Changed
---
- **Breaking (wire):** An Access Point's Active_Authentication_Policy can
  read 0, with Reliability CONFIGURATION_ERROR, when no usable policy is in
  effect or its policy list holds an invalid one, and its Reliability takes
  simulated writes while out of service (#1325).
