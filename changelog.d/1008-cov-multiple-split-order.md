---
section: Fixed
---
- **COV-multiple split order (wire behaviour):** a timestamped COV-multiple
  report too large for one notification now splits strictly in capture order,
  each reference's latest change included (#1008). Before, every reference's
  latest change stayed in the last notification with the untimestamped values.
  A context with many references could still send that notification over the
  smaller of the local and subscriber maximum APDU, and a reference's only
  change could arrive after newer changes of another reference. Now each
  notification carries the next run of changes, oldest first, and the last one
  carries the untimestamped values with the newest changes that still fit. A
  reference whose latest change went out earlier completes its observation
  when that notification is sent, or acknowledged when confirmed; in the last
  notification, a sibling carrying its field times it as #987 describes. A
  change too large for any notification on its own is now dropped and counted
  even when it is a reference's latest, since no report could deliver it and a
  confirmed context would keep retrying it. Only the untimestamped values,
  which still go together in the last notification, can exceed the limit; that
  is logged. An unconfirmed report that stops partway now completes the
  references whose latest change it already sent.
