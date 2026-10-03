---
section: Fixed
---
- **Wire:** AddListElement and RemoveListElement answer PROPERTY_IS_NOT_A_LIST
  when the target isn't a BACnetLIST, decided by the new
  `BACnetObject::is_list_property` (#999).
