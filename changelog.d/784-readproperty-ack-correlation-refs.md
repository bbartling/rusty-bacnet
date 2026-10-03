---
section: Changed
---
- Standalone and endpoint clients share ReadProperty ACK validation, so an ACK
  for another object, property or index is a decoding error (#784, #345).
