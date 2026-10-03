---
section: Migration notes
---
- **Python typed reads (#1310):** a whole Recipient_List, Port_Filter,
  List_Of_Group_Members, Group Present_Value, Action, Door_Members,
  Access_Doors, Target_References, Supported_Formats or Stages reads as a
  `list` of typed elements, and an indexed read as one element with its own
  tag, where `.value` used to be octets or a flat list. Read the elements
  from `.value` in the form the typed write takes; writing the value back is
  unchanged.
