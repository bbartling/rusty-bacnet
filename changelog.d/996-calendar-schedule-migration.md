---
section: Migration notes
commit: 107e9fa5fe54d0c990083ac264b833b06672833f
---
- **Schedule codecs (Rust API, #996):** import the calendar and schedule
  codecs from `bacnet_encoding::constructed`; `bacnet_services::schedule` and
  `BACnetDateRange::encode` and `decode` are gone.
