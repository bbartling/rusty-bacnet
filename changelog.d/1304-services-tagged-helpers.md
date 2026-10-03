---
section: Changed
---
- **Rust API:** `bacnet_encoding::constructed::tagged` is public, and the
  service decoders read their parameters with it in place of their own
  helpers, so a member read through it that is cut short is
  `Error::BufferTooShort`; Python error messages change, peer replies don't
  (#1304).
