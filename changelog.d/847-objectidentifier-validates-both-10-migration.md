---
section: Migration notes
---
- **ObjectIdentifier (#847):** replace `ObjectIdentifier::new_unchecked` with
  `new` or `new_addressable`. Python raises `ValueError` for an oversized
  object type.
