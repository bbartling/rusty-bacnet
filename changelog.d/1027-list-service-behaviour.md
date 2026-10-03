---
section: Fixed
---
- **Breaking list service behaviour:** AddListElement and RemoveListElement now
  compare whole elements and follow the add and remove rules of Clauses 15.1
  and 15.2 (#1027). AddListElement leaves an element that is already present as
  it is, a repeat within the request included, instead of appending a second
  copy. RemoveListElement refuses the whole request with SERVICES /
  LIST_ELEMENT_NOT_FOUND when any element is absent, instead of skipping it,
  and with PROPERTY / INVALID_DATA_TYPE when an element's datatype differs from
  the stored elements', and removes nothing in either case. This holds for
  lists of values, Recipient_List destinations and Calendar Date_List entries.
  An element the server cannot decode, or that the object refuses, is reported
  with its position as above. Adding a fault that Escalator Fault_Signals
  already holds now succeeds and changes nothing, where it was refused as out
  of range.
