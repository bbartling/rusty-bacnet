---
section: Migration notes
---
- `BACnetShedLevel` percent and level hold `u64`;
  `LoadControlObject::set_requested_shed_level` and `set_actual_shed_level`
  return `Result`; `AccessPointObject::set_access_event` takes a
  `BACnetTimeStamp`; `CredentialDataInputObject::set_present_value` replaces
  `set_update_time` (#1133).
