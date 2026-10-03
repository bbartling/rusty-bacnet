---
section: Migration notes
---
- **Averaging samples (Rust API, #1092):**
  `BACnetServer::add_averaging_sample_local` and
  `BACnetObject::add_averaging_sample_internal` take `Option<PropertyValue>`;
  pass `None` for an attempt that produced no value.
