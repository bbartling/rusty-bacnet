---
section: Fixed
---
- **Breaking (custom transports):** `NetworkLayer` and `BACnetRouter` drop a
  frame whose link-layer source MAC is longer than 18 octets and count it in
  `address_length_drops()`; no built-in transport reports one (#1198).
