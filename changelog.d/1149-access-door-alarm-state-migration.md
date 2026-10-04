---
section: Migration notes
---
- **Access Door (Rust API, #1149):** `AccessDoorObject::set_door_alarm_state` returns
  `Result` and refuses a state outside Alarm_Values and Fault_Values or inside
  Masked_Alarm_Values. Set the lists first (`set_alarm_values`, `set_fault_values`,
  or the new `add_access_door` keywords in Python); none of them takes NORMAL.
