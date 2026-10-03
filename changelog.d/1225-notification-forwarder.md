---
section: Added
---
- **Breaking (wire):** The Notification Forwarder (type 51) returns and forwards received and local event
  notifications to its Recipient_List and Subscribed_Recipients, which can persist across restarts; the
  server now executes ConfirmedEventNotification and UnconfirmedEventNotification (#1225).
