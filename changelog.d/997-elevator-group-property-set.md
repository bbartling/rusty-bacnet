---
section: Fixed
---
- **Breaking Elevator Group property set (wire):** the Elevator Group object
  now serves the properties its table defines (Clause 12.58, Table 12-76)
  (#997). It no longer serves Status_Flags, Out_Of_Service or Reliability,
  which the table doesn't list, so a client that read them from an Elevator
  Group now gets an error. They are gone from its Property_List, its property
  metadata, RPM ALL, and its PICS rows, and ReadProperty or WriteProperty on
  any of them fails with PROPERTY / UNKNOWN_PROPERTY. It gains the required
  Machine_Room_ID, a BACnetObjectIdentifier naming the Positive Integer Value
  object that holds the number of the group's machine room. It names instance
  4194303 of that type, the value for a room with no number, until the
  application calls the new `ElevatorGroupObject::set_machine_room_id`, which
  refuses any other object type; `machine_room_id()` reads it back. It is
  read-only over the network, so a WriteProperty fails with
  WRITE_ACCESS_DENIED. Group_ID, an Unsigned8, now refuses a write above 255
  with VALUE_OUT_OF_RANGE and keeps its value; before, it stored any Unsigned.
