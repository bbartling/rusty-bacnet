---
section: Fixed
---
- **Breaking (wire):** ReadRange reads only BACnetLIST properties and answers
  PROPERTY_IS_NOT_A_LIST for anything else; Recipient_List and
  List_Of_Object_Property_References now page by element (#1025).
