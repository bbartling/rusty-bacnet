---
section: Added
---
- **Undelivered event notification counters (#1142):** `BACnetServer::event_notification_counters()`
  returns `EventNotificationCounters`, saturating lifetime totals of event notifications the server
  did not deliver, and Python's `BACnetServer.event_notification_counters()` returns the same fields
  as the `EventNotificationCounters` TypedDict. Four fields count transitions whose Notification
  Class lookup failed closed (`notification_class_missing`, `recipient_list_unavailable`,
  `recipient_list_invalid`, `recipient_list_too_long`), which before left only a log line; three
  count confirmed notifications to one recipient that found no free invoke ID
  (`confirmed_no_invoke_id`), were answered with an Error, Reject or Abort (`confirmed_rejected`), or
  drew no acknowledgment after the last retry (`confirmed_unanswered`). An empty or fully filtered
  Recipient_List, DCC and Event_Enable are not counted.
