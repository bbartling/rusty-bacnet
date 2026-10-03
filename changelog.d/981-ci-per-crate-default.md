---
section: Changed
commit: b28c16ffba4dc8a8672c1a31ccda0c8f15869c02
---
- CI's per-crate default-features check also covers the Windows and macOS
  targets, and the native Windows job stops the Compatibility Appraiser that
  upset test timing (#981, #1003).
