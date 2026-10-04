---
section: Migration notes
---
- **bacnet-encoding (Rust API, #1374):** `tags::decode_optional_context` is
  removed. Peek with `constructed::tagged::next_is_context`, then read the
  member with `decode_ctx_primitive` or a typed reader, or wrap one in
  `decode_optional_ctx`.
