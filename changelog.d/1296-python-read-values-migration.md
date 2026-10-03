---
section: Migration notes
---
- **Python reads and local writes (#1296, #1297):** a whole array or list (such
  as Object_List or Priority_Array) is a `list` even with one element, a
  constructed value is `application_data` bytes, and an empty value is
  `PropertyValue.list([])`. `BACnetServer.read_property` and
  `write_property_local` raise `BacnetProtocolError` as network requests do: a
  missing object is UNKNOWN_OBJECT, not `RuntimeError`.
