---
section: Migration notes
---
- **Access Rights (Rust API, #1316):** `BACnetAccessRule` takes the Clause 21
  shape: the specifiers are `AccessRuleTimeRangeSpecifier` and
  `AccessRuleLocationSpecifier`, and the time range is a
  `BACnetDeviceObjectPropertyReference`. `BACnetAccessRule::new` builds one
  from optional references.
