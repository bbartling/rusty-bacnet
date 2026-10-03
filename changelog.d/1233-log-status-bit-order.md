---
section: Fixed
---
- **Breaking (wire):** Log records (Trend, Event, Trend Log Multiple and Audit Log) send and read
  BACnetLogStatus bit 0 first, so log-disabled goes out as `05 80`, not as log-interrupted (#1233).
