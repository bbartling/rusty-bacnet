---
section: Migration notes
---
- **Accumulator Scale and Prescale (wire, #1487):** a client that decoded
  the old application-tagged REAL or INTEGER Scale, or the two application
  Unsigneds of Prescale, decodes the context-tagged forms instead. In Rust,
  `AccumulatorObject` reads both as `PropertyValue::ApplicationData`; decode
  them with `bacnet_encoding::constructed::{decode_scale, decode_prescale}`.
