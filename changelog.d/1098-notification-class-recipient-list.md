---
section: Fixed
---
- **Breaking (wire, Rust API):** a Notification Class Recipient_List holds at
  most 32 destinations, and `NotificationClass::add_destination` returns
  `Result` (#1098).
