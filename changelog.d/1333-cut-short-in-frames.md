---
section: Changed
---
- **Rust API:** decoders report contents cut short as `Error::BufferTooShort`
  inside constructed frames, Error PDUs and timestamps too, and check a
  fixed-size application value's length before its contents. Python error
  messages change; peer replies don't (#1333).
