---
section: Fixed
---
- **Breaking Rust `subscribe_multiple` argument:** timestamped COV-multiple
  history that one notification cannot carry now goes out in several
  notifications instead of being dropped (#986). Each fits the smaller of the
  server's `max_apdu_length` and the max-APDU-length-accepted the subscriber
  sent in its SubscribeCOVPropertyMultiple request, which the server now keeps
  with the context. Older history goes first; the last notification carries each
  reference's latest change and the untimestamped values, and each header
  timestamp names the last change its notification carries. An unconfirmed
  report sends every part at once, one report per context at a time, and stops
  when communication is disabled; a confirmed report sends one part per Ack, as
  local policy. Before, queued history was trimmed to fit one local APDU and the
  oldest changes were counted as dropped. A context now holds about four
  notifications' worth of pending history, counting item framing, a fixed
  per-change overhead and room for its untimestamped values, and drops its
  oldest change only when that overflows. A history change too large for any
  notification on its own is dropped and counted, and a last notification that
  still exceeds the limit is logged. `CovSubscriptionTable::subscribe_multiple`
  takes the subscriber's maximum APDU as a new `Option<u16>` argument (`None`
  keeps the one already known), and
  `CovSubscriptionSnapshot::subscriber_max_apdu` reports it.
