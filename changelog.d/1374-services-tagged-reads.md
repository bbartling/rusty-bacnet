---
section: Changed
---
- **Breaking (Rust API):** the bacnet-services decoders that still read tags
  inline use `bacnet_encoding::constructed::tagged`, so a member they read
  that is cut short is `Error::BufferTooShort`; `tags::decode_optional_context`
  is removed. Peer replies don't change (#1374).
