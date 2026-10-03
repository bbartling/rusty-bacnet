---
section: Migration notes
---
- **Group (Rust API, #1134):** `GroupObject::add_member` takes a
  `ReadAccessSpecification` and returns `Result`. `PropertyReference` and
  `ReadAccessSpecification` moved to `bacnet_types::constructed`, with their
  codecs in `bacnet_encoding::constructed`; update imports.
