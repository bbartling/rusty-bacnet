---
section: Migration notes
commit: 42e45288181d8fa383c5b41fce6de387bdb034a1
---
- **Access Credential and Access Door (Rust API, #1073, #979):**
  Credential_Status is read-only now; raise disable reasons with
  `add_disable_reason`. Set Assigned_Access_Rights and Authentication_Factors
  with `set_assigned_access_rights` and `set_authentication_factors`, and
  build `BACnetAssignedAccessRights` with a `BACnetDeviceObjectReference`.
  `AccessDoorObject::set_relinquish_default` takes a `DoorValue`.
