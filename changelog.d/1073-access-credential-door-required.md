---
section: Changed
commit: 42e45288181d8fa383c5b41fce6de387bdb034a1
---
- **Breaking (wire, Rust API):** Access Credential and Access Door serve every
  required row of their tables. Credential_Status is derived from
  Reason_For_Disable, a door command outside the four BACnetDoorValue values
  is refused, and a pulse unlock relinquishes after its pulse time (#1073,
  #979).
