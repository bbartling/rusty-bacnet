---
section: Fixed
---
- **Breaking Calendar property set (wire):** Calendar no longer serves
  Status_Flags, Event_State or Out_Of_Service (#984), so a client that read
  them from a Calendar now gets an error. Its property table (Clause 12.9,
  Table 12-11) defines none of them, yet Calendar listed all three as
  optional and returned fixed values: flags all FALSE, NORMAL and FALSE. They
  are gone from its Property_List, its property metadata, RPM ALL and
  OPTIONAL, and its PICS rows, and ReadProperty or WriteProperty on any of
  them now fails with PROPERTY / UNKNOWN_PROPERTY, as it does for
  Reliability.
