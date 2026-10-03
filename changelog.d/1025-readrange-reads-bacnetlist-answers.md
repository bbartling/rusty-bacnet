---
section: Fixed
commit: 77a0a8179e490b3ba49d7140ed8040cb48e0f667
---
- **Breaking (wire):** ReadRange reads only BACnetLIST properties and answers
  PROPERTY_IS_NOT_A_LIST for anything else; Recipient_List and
  List_Of_Object_Property_References now page by element (#1025).
