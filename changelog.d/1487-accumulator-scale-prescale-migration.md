---
section: Migration notes
---
- **Accumulator Scale and Prescale (#1487):** a client decoding the old
  application-tagged Scale or Prescale decodes the context-tagged forms
  instead. In Python, Scale's tag is `"scale"`, not `"real"`, and Prescale
  reads as `(5, 100)`, not `[5, 100]`. In Rust, `read_property` returns
  `PropertyValue::ApplicationData`, not a `List`; decode it with
  `bacnet_encoding::constructed::{decode_scale, decode_prescale}`.
