---
section: Changed
---
- **Rust API:** the ReadAccessSpecification, BACnetChannelValue, audit
  notification and formal Error body decoders report contents cut short as
  `Error::BufferTooShort` and a fixed-size field of the wrong length as
  `Error::Decoding`; Python error messages change, peer replies don't (#1303).
