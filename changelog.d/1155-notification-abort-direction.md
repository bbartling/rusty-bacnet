---
section: Fixed
---
- **Confirmed notification Abort direction (wire behaviour):** a recipient's
  Abort now ends a confirmed COV, COV-multiple, Event or audit notification
  this device sent (#1155). The recipient is the server of that transaction,
  so its Abort carries the server flag (Clause 5.4), but the outbound
  transaction coordinator in `bacnet-endpoint-core` expected the flag clear
  for notifications. It refused the recipient's Abort, kept resending a
  request the recipient had already aborted until the retries ran out, and
  then treated the notification as unanswered instead of refused. It also
  accepted an Abort with the flag clear, which belongs to a transaction this
  device serves, as the end of a notification with the same invoke ID. Now
  every outbound lease, notification or client request, ends only on an Abort
  with the server flag set, and one with the flag clear is refused.
