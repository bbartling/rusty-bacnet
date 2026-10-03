---
section: Migration notes
---
- **Python read results (#1296, #1297):** a whole Object_List, Priority_Array or
  other array or list is now a `list` even with one element, and a constructed
  value such as Recipient_List is `application_data` bytes with every element.
  An empty value is `PropertyValue.list([])`. `BACnetServer.read_property` takes
  the same shapes and raises `BacnetProtocolError` (UNKNOWN_OBJECT), not
  `RuntimeError`, for a missing object.
