---
section: Changed
---
- **Rust API:** the ReadAccessSpecification, BACnetChannelValue, audit
  notification and formal Error body decoders report contents cut short as
  `Error::BufferTooShort`, like the other constructed codecs; peers see the
  same replies (#1303).
