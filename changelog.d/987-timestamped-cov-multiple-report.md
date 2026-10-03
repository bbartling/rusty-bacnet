---
section: Fixed
---
- In a timestamped COV-multiple report, a field subscribed with timestamps no
  longer goes out without a Time_Of_Change (#987). Before, when its own selector
  had not changed in that round and an untimestamped sibling reference carried
  the field, for example Status_Flags travelling with an untimestamped
  Present_Value, it had no time. Captures now record the selector's own value at
  the commit time even when it moves less than the selector's COV increment, and
  a carried value carries the time of the commit that set it; an admission or
  renewal capture counts as one. A value no producer captured carries the
  preparation time instead, kept for that value. With no time to give, because
  the Device clock is invalid or a producer snapshot predates the record, it is
  left out of the notification. The header timestamp counts these times, so
  across notifications to a context on several objects it can move back. A field
  that a timestamped companion already times keeps that time.
