---
section: Added
---
- **Rust API:** `ReadRangeAck` decodes its item data as Trend Log, Event Log,
  Trend Log Multiple or Audit Log records, or names the offset of the first
  record that fails, keeping the ones before it (#1534).
