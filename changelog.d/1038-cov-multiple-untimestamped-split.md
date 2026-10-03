---
section: Fixed
---
- **COV-multiple untimestamped split (wire behaviour):** untimestamped
  COV-multiple values that alone exceed the smaller of the local and subscriber
  maximum APDU now go out in several notifications that each fit, instead of
  one oversized notification with a warning (#1038). The common case is the
  initial report of a SubscribeCOVPropertyMultiple request over many objects.
  Every timestamped change still goes first; the untimestamped values follow
  in runs of whole object items, with one object's references apart only where
  its item alone does not fit, and each notification completes only the
  references it carries. An unconfirmed report sends every part at once; one
  that stops partway (communication disabled, the event budget spent, a failed
  send) leaves the references of its unsent parts owed, and the
  Max_Notification_Delay backstop or re-enabled communication sends them. A
  confirmed report sends one part per acknowledgment, as #986 does for
  timestamped parts, and owes the references of its later parts meanwhile, so
  they also outlast a follow-up dropped under DCC. An owed reference's value is
  read afresh when it goes out, so a newer change goes in place of the value
  first prepared, and it goes ahead of newer changes. An unconfirmed context
  without timestamped references now sends a report of several parts one at a
  time, as a timestamped context does, so a later report cannot overtake its
  parts. A reference whose values alone fit no notification is left out and
  logged rather than sent over the limit, and is evaluated again at its next
  fanout.
