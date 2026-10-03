---
section: Added
---
- `bacnet read-range` decodes Trend Log, Event Log, Trend Log Multiple and
  Audit Log records instead of printing hex; its JSON for a log buffer lists
  them under `records` instead of `items` (#1274).
