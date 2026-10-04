---
section: Fixed
---
- **Breaking (wire, Rust API):** a Schedule reference naming a missing object or property, or an
  array index the property can't take, sets the Schedule's Reliability to
  CONFIGURATION_ERROR until a write to it succeeds or it leaves the list
  (#1433).
