---
section: Changed
---
- **Breaking (wire):** An Access Point left with no usable policy in effect
  reads Active_Authentication_Policy 0 and Reliability CONFIGURATION_ERROR
  instead of refusing the change, and its Reliability takes simulated writes
  while out of service (#1325).
