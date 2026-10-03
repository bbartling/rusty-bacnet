---
section: Fixed
---
- **Breaking ReadRange behavior:** ReadRange now reads only a BACnetLIST and
  answers SERVICES / PROPERTY_IS_NOT_A_LIST for any other target (#1025). It
  decides from the property's datatype through `BACnetObject::is_list_property`
  (#999), before it selects any item. Before, it went by the shape of the value
  it read. It paged whole arrays such as Object_List, Priority_Array and
  State_Text, an array element that reads as several values (one day of
  Weekly_Schedule) and a BACnetDateTime. It also refused two lists held framed
  as not lists: Notification Class's Recipient_List and Schedule's
  List_Of_Object_Property_References. Those two are now split into their
  elements, so By Position counts destinations and references. A list the
  server can't split returns SERVICES / OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED,
  and ReadProperty still reads it whole. That covers a vendor list held framed;
  the Device's COV subscription lists are paged since #1046, below. An array
  index on a property that doesn't exist now
  reports UNKNOWN_PROPERTY instead of PROPERTY_IS_NOT_AN_ARRAY. By Sequence
  Number or By Time on a target that isn't a list now reports
  PROPERTY_IS_NOT_A_LIST instead of the range-type error. Log_Buffer reads and
  Calendar's Date_List are unchanged. The new
  `bacnet_encoding::constructed::decode_device_object_property_reference`
  decodes one element of a BACnetLIST of BACnetDeviceObjectPropertyReference.
