---
section: Fixed
---
- `ObjectIdentifier` now validates both its 10-bit object type and 22-bit
  instance at construction (#847). `new_addressable` shares these checks and
  still rejects wildcard instances. The safe `new_unchecked` constructor is
  removed; migrate callers to `new` or `new_addressable`. Encoders remain
  infallible and no longer mask invalid fields in release builds. Python
  construction rejects oversized object types with `ValueError`; generic
  `ObjectType` selectors, valid proprietary types and wire wildcards remain
  available. ValueSource relies on this invariant and retains its MAC-length
  validation; no source-production behavior is added.
