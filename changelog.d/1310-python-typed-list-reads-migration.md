---
section: Migration notes
---
- **Python typed reads (#1310):** Recipient_List, Port_Filter,
  List_Of_Group_Members, Group Present_Value, Action, Door_Members,
  Access_Doors, Target_References, Supported_Formats and Stages read as
  typed elements in the typed write's form, not octets or a flat list;
  writing back is unchanged. A typed read no longer equals
  `PropertyValue.application_data(octets)`, so such comparisons and dict
  keys change.
