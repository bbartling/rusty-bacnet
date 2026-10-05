---
section: Migration notes
commit: 77621307d247d88a91dcb0478a844ffd54bcf880
---
- **Schedule references (Rust API, #1088):**
  `ScheduleObject::add_object_property_reference` returns `Result`. A wrapper
  that forwards every trait method needs the new `take_owed_schedule_writes`
  and `complete_schedule_write` hooks.
