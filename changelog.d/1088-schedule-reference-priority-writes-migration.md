---
section: Migration notes
commit: 77621307d247d88a91dcb0478a844ffd54bcf880
---
- **Schedule references (Rust API, #1088):**
  `ScheduleObject::add_object_property_reference` returns `Result`, and
  `BACnetObject::take_owed_schedule_writes` returns every owed write as a
  `Vec`. A wrapper that forwards every trait method needs the new
  `complete_schedule_write` hook.
