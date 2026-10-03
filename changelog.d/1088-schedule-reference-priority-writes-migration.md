---
section: Migration notes
---
- **Schedule references (Rust API, #1088):**
  `ScheduleObject::add_object_property_reference` returns `Result`, and
  `BACnetObject::take_owed_schedule_writes` returns every owed write as a
  `Vec`. A wrapper that forwards every trait method needs the new
  `complete_schedule_write` hook.
