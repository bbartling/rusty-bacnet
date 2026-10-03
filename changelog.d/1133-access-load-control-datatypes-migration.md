---
section: Migration notes
commit: 0debbcadb03353f5b065c76b9207f97219248d33
---
- `BACnetShedLevel` percent and level hold `u64`;
  `LoadControlObject::set_requested_shed_level` and `set_actual_shed_level`
  return `Result`; `AccessPointObject::set_access_event` takes a
  `BACnetTimeStamp`; `CredentialDataInputObject::set_present_value` replaces
  `set_update_time` (#1133).
