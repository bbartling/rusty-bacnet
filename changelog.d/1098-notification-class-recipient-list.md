---
section: Fixed
commit: 2caee311979e4311fd7f87d4e09bee815dee50ac
---
- **Breaking (wire, Rust API):** a Notification Class Recipient_List holds at
  most 32 destinations, and `NotificationClass::add_destination` returns
  `Result` (#1098).
