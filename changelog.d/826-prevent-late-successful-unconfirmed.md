---
section: Fixed
---
- Prevent late successful unconfirmed COV sends from replacing a newer successful
  prepared observation (#826). One checked table counter and per-reference marker
  commit the whole baseline together; failed or cancelled newer sends do not
  block older successes. Existing lifecycle fences and confirmed admission-time
  completion remain. The pre-1.0 public baseline setter is removed; completion
  is internal to the notification executor. This is preparation ordering, not
  original-write, transport-byte or remote-receipt ordering.
