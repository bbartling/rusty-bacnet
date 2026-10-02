---
section: Fixed
---
- **Breaking Escalator property set (wire):** the Escalator object gains the
  required Elevator_Group, Group_ID and Installation_ID of Clause 12.60,
  Table 12-78 (#1022). Elevator_Group names Elevator Group instance 4194303
  until the application sets one, and Group_ID and Installation_ID are
  Unsigned8 values that start at 0. All three are read-only over the network
  and set with the new `EscalatorObject::set_elevator_group`, `set_group_id`
  and `set_installation_id`. Energy_Meter_Ref is now a
  BACnetDeviceObjectReference, uninitialized (instance 4194303), instead of an
  empty OctetString. The rows are listed in table order in Property_List, the
  property metadata, RPM ALL, REQUIRED and OPTIONAL, and the PICS.
