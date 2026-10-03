---
section: Added
---
- **Breaking Lift call, door-command and car-state rows (wire):** the Lift
  object serves nine more optional rows of Clause 12.59, Table 12-77, each
  with its table datatype (#1052): the BACnetARRAYs Assigned_Landing_Calls
  (of BACnetAssignedLandingCalls), Making_Car_Call (of Unsigned8),
  Registered_Car_Call (of BACnetLiftCarCallList) and Car_Door_Command (of
  BACnetLiftCarDoorCommand), and Car_Assigned_Direction, Car_Door_Zone,
  Car_Mode, Next_Stopping_Floor and Car_Drive_Status. On the wire, they join
  Property_List, RPM ALL and OPTIONAL in table order, and the PICS. The four
  arrays hold one element per car door, take an array index, and follow the
  door count `set_car_door_status` sets: a new door starts with no calls, a
  Making_Car_Call of 0 and a Car_Door_Command of NONE. A new Lift reads
  UNKNOWN for Car_Assigned_Direction, Car_Mode and Car_Drive_Status, FALSE for
  Car_Door_Zone and 1 for Next_Stopping_Floor. In service all nine are
  read-only over the network, and the application sets them with new
  `LiftObject` setters (`set_assigned_landing_calls`, `set_making_car_call`,
  `set_registered_car_call`, `set_car_door_command`,
  `set_car_assigned_direction`, `set_car_door_zone`, `set_car_mode`,
  `set_next_stopping_floor` and `set_car_drive_status`) with matching
  getters. While Out_Of_Service is TRUE they take WriteProperty, which items
  (c) and (d) of the Lift's Out_Of_Service description ask for so a test tool
  can simulate the car; an array takes the whole array or one element and,
  like Car_Door_Status, keeps its size. A floor number above 255, a direction,
  mode or drive status that is reserved or above 65535, or a door command
  other than NONE, OPEN or CLOSE (BACnetLiftCarDoorCommand has no proprietary
  range) fails with VALUE_OUT_OF_RANGE, a value of the wrong datatype with
  INVALID_DATA_TYPE and an undecodable frame with INVALID_DATA_ENCODING, all
  leaving the property unchanged. `bacnet-types` adds
  `constructed::{BACnetAssignedLandingCalls, AssignedLandingCall,
  BACnetLiftCarCallList}`; the first name returns, with its Clause 21 shape,
  after #980 removed an unused type of that name. `bacnet-encoding` adds
  `encode_assigned_landing_calls`, `decode_assigned_landing_calls`,
  `encode_lift_car_call_list` and `decode_lift_car_call_list`.
