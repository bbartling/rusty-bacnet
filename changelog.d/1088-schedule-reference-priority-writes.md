---
section: Added
commit: 77621307d247d88a91dcb0478a844ffd54bcf880
---
- **Breaking (wire, Rust API):** a Schedule's
  List_Of_Object_Property_References and Priority_For_Writing are
  network-writable, and a target that refuses the schedule's datatype faults
  the Schedule (#1088, #1086).
