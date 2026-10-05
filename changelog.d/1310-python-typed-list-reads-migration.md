---
section: Migration notes
---
- **Python typed reads (#1310):** Recipient_List, List_Of_Group_Members,
  Group Present_Value, Action, Door_Members, Access_Doors, Target_References,
  Supported_Formats and Stages read as typed elements in the typed write's
  form. A 0.11.0 local read gave the stored form (`application_data` octets
  for Recipient_List, a flat list for the others) and a client read only the
  first application-tagged value; compare against the typed form. Writing
  back is unchanged.
