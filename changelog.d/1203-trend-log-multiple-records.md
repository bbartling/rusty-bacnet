---
section: Migration notes
---
- `TrendLogMultipleObject::add_record` and `records()` use
  `BACnetLogMultipleRecord` (one `LogValue` per member) instead of
  `BACnetLogRecord`; object wrappers forward the new
  `BACnetObject::add_trend_multiple_record` hook (#1203).
