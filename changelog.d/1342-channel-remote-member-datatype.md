---
section: Changed
---
- **Wire:** A Channel reads a member's property in another device to learn its
  datatype and coerces its value to it as for a local member, so a remote
  Binary Output takes REAL 1.0 as ACTIVE; a failed read sends the value as
  written (#1342).
