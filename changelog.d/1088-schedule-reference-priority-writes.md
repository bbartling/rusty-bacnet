---
section: Added
---
- **Breaking (wire, Rust API):** a Schedule's
  List_Of_Object_Property_References and Priority_For_Writing are
  network-writable, and a target that refuses the schedule's datatype faults
  the Schedule (#1088, #1086).
