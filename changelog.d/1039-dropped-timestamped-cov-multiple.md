---
section: Changed
---
- Dropped timestamped COV-multiple changes now log one warning per context for
  each cause (bound overflow, too large for any notification, superseded),
  instead of one per drop, until the context is admitted afresh: a timestamped
  reference of it is subscribed again, or an admission changes the maximum
  APDU its notifications must fit (#1039). Later drops log at debug level, and
  `CovCounters::timed_changes_dropped` still counts every one. A subscriber
  whose maximum APDU cannot hold one timestamped change of its references, such
  as one advertising 50 octets for a REAL Present_Value with Status_Flags
  (58 to 66 octets), used to log a warning for every change; its subscription
  is still accepted, since the SubscribeCOVPropertyMultiple error tables have
  no error for that cause, and `docs/rust-api.md` now documents the limit and
  the sizes: the same values without timestamps fit 50 octets.
