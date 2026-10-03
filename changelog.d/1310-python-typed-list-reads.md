---
section: Changed
---
- **Breaking (Python API):** reads of Recipient_List, Port_Filter, a Group's
  members and Present_Value, a Command's Action and the other constructed
  lists the binding writes as typed values return those typed values instead
  of `application_data` octets (#1310).
