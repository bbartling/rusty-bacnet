---
section: Fixed
commit: 22c6df893438fb5455e6726c408a436d2e48730a
---
- **Wire:** AddListElement and RemoveListElement answer PROPERTY_IS_NOT_A_LIST
  when the target isn't a BACnetLIST, decided by the new
  `BACnetObject::is_list_property` (#999).
