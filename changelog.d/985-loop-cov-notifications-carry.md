---
section: Fixed
---
- **Loop COV notifications carry Setpoint and Controlled_Variable_Value
  (wire):** a Loop's SubscribeCOV notification now reports Present_Value,
  Status_Flags, Setpoint and Controlled_Variable_Value, in that order, as the
  COV criteria table (Clause 13.1, Table 13-1) lists for Loop (#985). Before,
  it carried only the first two. Loop now serves the required
  Controlled_Variable_Value (Table 12-20), a read-only REAL the application
  sets with `LoopObject::set_controlled_variable_value`, and the COV_Increment
  property the table requires of a Loop that reports COV: a writable REAL,
  default 0 (any change), validated as on the analog objects. A Present_Value
  change now reports only when it moves by at least COV_Increment; before,
  every change did. A Setpoint or Controlled_Variable_Value change alone
  still sends nothing. Loop's Present_Value is now writable while
  Out_Of_Service is TRUE, for simulation, and refuses writes with
  WRITE_ACCESS_DENIED in service; its property metadata and PICS row mark it
  writable while out of service. In service the application supplies it
  through `BACnetServer::set_present_value_local`, which now accepts a Loop
  and is refused while Out_Of_Service is TRUE. The new rows appear in
  Property_List, the property metadata, RPM ALL, REQUIRED and OPTIONAL, and
  the PICS.
