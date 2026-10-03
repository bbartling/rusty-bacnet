---
section: Fixed
commit: c3bce1f0bef2887d82760f2c6d48b89fbed83042
---
- **Breaking (wire, Rust API):** the Elevator Group's Landing_Call_Control and
  Landing_Calls carry BACnetLandingCallStatus values, and the unused
  `BACnetAssignedLandingCalls` is removed (#980).
