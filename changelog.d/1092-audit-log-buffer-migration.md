---
section: Migration notes
---
- `RangeSpec` reference index and sequence, `ReadRangeAck::first_sequence_number`
  and `LogRecordIdentity::sequence_number` are now `u64`; widen any code that
  builds or matches them (#1092).
