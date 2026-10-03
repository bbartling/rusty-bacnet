---
section: Changed
commit: 339a02a068df641867ccee41f6076fa6ce7fea7e
---
- **Breaking (Rust API):** objects store Reliability as a typed enumeration,
  and Life Safety Point and Zone, the access-control objects and Elevator
  Group store their enumerated fields typed too; the wire values and the
  Python API are unchanged (#932).
