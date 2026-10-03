---
section: Migration notes
commit: 9217089a8c6dd561c5dcb096738f3d58a8fb42c1
---
- **Group (Rust API, #1134):** `GroupObject::add_member` takes a
  `ReadAccessSpecification` and returns `Result`. `PropertyReference` and
  `ReadAccessSpecification` moved to `bacnet_types::constructed`, with their
  codecs in `bacnet_encoding::constructed`; update imports.
