---
section: Migration notes
commit: 2caee311979e4311fd7f87d4e09bee815dee50ac
---
- **Recipient_List (Rust API, #1098, #1125):** read the list with
  `recipient_list()`, since the field is private, and handle the `Result` from
  `add_destination`. A local write takes only the framed BACnetLIST in
  `PropertyValue::ApplicationData`; write empty application data to clear it.
