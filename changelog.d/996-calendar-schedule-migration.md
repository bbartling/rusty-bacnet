---
section: Migration notes
---
- **Schedule codecs (Rust API, #996):** import the calendar and schedule
  codecs from `bacnet_encoding::constructed`; `bacnet_services::schedule` and
  `BACnetDateRange::encode` and `decode` are gone.
