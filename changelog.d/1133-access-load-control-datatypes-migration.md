---
section: Migration notes
commit: 0debbcadb03353f5b065c76b9207f97219248d33
---
- `BACnetShedLevel` percent and level hold `u64`, and
  `LoadControlObject::set_requested_shed_level` and `set_actual_shed_level`
  return `Result` (#1133).
