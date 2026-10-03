---
section: Fixed
---
- **Breaking property sets of fourteen object types (wire):** a sweep of every
  object type's served properties against its property table in Clause 12
  (#1064) found rows that no table defines, all carried over from the 0.1.0
  import. Each is gone from the object's Property_List, property metadata,
  RPM ALL and OPTIONAL, and PICS rows, and ReadProperty, RPM or WriteProperty
  on it now fails with PROPERTY / UNKNOWN_PROPERTY:
  - Event Log (Table 12-31): Out_Of_Service and Log_Interval, both writable.
  - Command (Table 12-12), Event Enrollment (Table 12-14), Notification Class
    (Table 12-24), Load Control (Table 12-32), Access Credential
    (Table 12-40) and Access Rights (Table 12-39): a writable Out_Of_Service.
  - File (Table 12-16), Group (Table 12-17) and Structured View
    (Table 12-34): Status_Flags, Reliability and a writable Out_Of_Service.
  - Averaging (Table 12-5): Present_Value, a copy of Average_Value, plus
    Status_Flags, Event_State, Reliability and a writable Out_Of_Service.
  - Access User (Table 12-38): a writable Present_Value that duplicated the
    user type without tracking User_Type, Assigned_Access_Rights and a
    writable Out_Of_Service.
  - Access Point (Table 12-36): a writable Present_Value kept apart from
    Access_Event.
  - Access Zone (Table 12-37): a writable Present_Value and Access_Doors.

  Writing the old Out_Of_Service used to set the OUT_OF_SERVICE status flag on
  the objects that keep Status_Flags, though those object types hold that flag
  FALSE; it now stays FALSE. An Event Enrollment written out of service used
  to stop being evaluated; its type has no such switch, so evaluation now
  always runs unless Event_Detection_Enable is FALSE. Credential Data Input
  keeps its Out_Of_Service, which Table 12-43 does define. The Rust and Python
  APIs are unchanged.
