---
section: Migration notes
---
- **Event notification codecs (Rust API, #1276):** `EventNotificationRequest`,
  `NotificationParameters` and `BACnetPropertyValue` lose their `encode` and
  `decode` methods; call `encode_event_notification`,
  `decode_event_notification`, `encode_notification_parameters`,
  `decode_notification_parameters`, `encode_bacnet_property_value` or
  `decode_bacnet_property_value` in `bacnet_encoding::constructed`. Build an
  Event Log notification record from the typed request, not its bytes.
