---
section: Fixed
---
- Schedule execution retains each local target's array index through the public
  `BACnetObject::tick_schedule` hook, endpoint forwarding and server write queue
  (#845). The hook now returns `Vec<BACnetObjectPropertyReference>` instead of
  object/property pairs. `List_Of_Object_Property_References` reads return
  `ApplicationData` containing concatenated context-tagged local reference bodies,
  including optional indices. Failed targets do not stop later writes; the list
  remains non-array, and write priority remains fixed at 16. Remote targets
  and configurable priority are not added. Command-source propagation is described
  in the #824 entry above.
