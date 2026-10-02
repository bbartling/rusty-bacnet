---
section: Fixed
---
- AddListElement and RemoveListElement now answer SERVICES /
  PROPERTY_IS_NOT_A_LIST when the target is not a BACnetLIST (#999). Before, a
  scalar or an array came back as WRITE_ACCESS_DENIED, and a constructed value
  held framed, such as Elevator Group's Landing_Call_Control, was pushed through
  the Recipient_List destination codec and came back as INVALID_DATA_TYPE. Those
  requests wrote nothing, but one shape did: a RemoveListElement on a value that
  reads as several members, such as DateTime Value's Present_Value, naming
  members it didn't hold, was acknowledged and wrote the unchanged value back,
  which on that commandable object set a priority-16 command. The server now
  decides from the property's datatype before it decodes any element, through
  the new `BACnetObject::is_list_property`, whose default follows the Clause 12
  datatypes and which custom objects can override. A whole array and an indexed
  array element are refused the same way. Unknown object, unknown property and
  array-index errors still come first, and element datatype errors after. The
  destination codec now serves only BACnetLIST of BACnetDestination properties;
  a list held framed with no element codec, such as Schedule's
  List_Of_Object_Property_References, returns PROPERTY / WRITE_ACCESS_DENIED.
