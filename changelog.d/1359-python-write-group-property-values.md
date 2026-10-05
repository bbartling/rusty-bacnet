---
section: Added
---
- **Python API:** `BACnetClient.write_group` takes a `PropertyValue` as a
  change-list value and encodes it, beside encoded `bytes` or `bytearray`; a
  list of ints is no longer taken as the encoded octets (#1359).
