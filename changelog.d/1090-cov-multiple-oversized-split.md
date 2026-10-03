---
section: Changed
---
- **COV-multiple timestamped changes too large for one notification (wire
  behaviour):** a timestamped change that does not fit a COV-multiple
  notification even on its own now goes out one value per notification, in the
  order its values were captured, each value with the change's Time_Of_Change
  and each envelope naming the change (#1090). Before, the whole change was
  dropped and counted, so a subscriber advertising a 50-octet maximum APDU got
  no timestamped changes at all; it now typically gets Present_Value and
  Status_Flags in two notifications. Only the notification with the change's
  last value completes the reference, and values whose notification fails, or
  that a confirmed report defers, come back as one change. A value too large
  even alone, such as a long character string, is dropped and its change
  counted once in `CovCounters::timed_changes_dropped`, while the change's
  other values still go out. Changes that fit a notification go out whole, as
  before.
