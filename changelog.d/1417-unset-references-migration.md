---
section: Migration notes
---
- **Unset references (wire and Python API, #1417):** Controlled_Variable_Reference,
  Manipulated_Variable_Reference, Input_Reference, a Trend Log's
  Log_DeviceObjectProperty and Object_Property_Reference no longer read NULL
  while unset. Treat a reference whose object or Device instance is 4194303 as
  unset, and clear one by writing such a reference, not NULL; clear
  Fault_Parameters with its context-tagged `none` choice.
