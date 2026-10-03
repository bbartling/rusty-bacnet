---
section: Fixed
---
- **Breaking Lift property set (API and wire format):** the Lift object now
  serves its rows of Clause 12.59, Table 12-77, with their table datatypes
  (#1021). On the wire: Car_Position is an Unsigned8, so a write above 255
  fails with VALUE_OUT_OF_RANGE and keeps the value. Car_Load is a REAL
  instead of an Unsigned percentage capped at 100; it takes any finite value
  and refuses NaN and infinities with VALUE_OUT_OF_RANGE. Car_Door_Status is a
  BACnetARRAY of BACnetDoorStatus instead of an empty list of Unsigned, and a
  new Lift has one car door with status UNKNOWN. Landing_Door_Status is a
  BACnetARRAY of BACnetLandingDoorStatus, one element per car door, instead of
  an Unsigned floor count. Floor_Text, Car_Door_Status and Landing_Door_Status
  now take an array index. Tracking_Value and Floor_Number, which the table
  doesn't define, are gone, and ReadProperty or WriteProperty on them fails
  with PROPERTY / UNKNOWN_PROPERTY. The Lift gains the required
  Elevator_Group, Group_ID, Installation_ID, Passenger_Alarm and Fault_Signals,
  and Car_Load_Units, which must be present with Car_Load. Passenger_Alarm (a
  Boolean, FALSE at first) and Fault_Signals (a BACnetLIST of BACnetLiftFault
  that refuses reserved, oversized and repeated faults) take writes, as
  Energy_Meter now does too. The rows are listed in table order in
  Property_List, the property metadata, RPM ALL, REQUIRED and OPTIONAL, and
  the PICS. In the Rust API: Elevator_Group, Group_ID, Installation_ID,
  Car_Load_Units, Car_Door_Status and Landing_Door_Status are read-only over
  the network and set with new `LiftObject` setters. `set_elevator_group`
  refuses any object type but Elevator Group, `set_car_load_units` a value
  above 65535, `set_car_door_status` a reserved door status, and
  `set_landing_door_status` a size other than Car_Door_Status's;
  `set_car_door_status` also resizes Landing_Door_Status to the new door
  count. `bacnet-types` adds `constructed::{BACnetLandingDoorStatus,
  LandingDoor}` and `bacnet-encoding` adds `encode_landing_door_status` and
  `decode_landing_door_status`.
