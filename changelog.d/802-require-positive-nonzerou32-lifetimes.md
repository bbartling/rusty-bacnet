---
section: Fixed
---
- **Breaking (Rust API):** single-property COV subscribe methods take a
  `NonZeroU32` lifetime, and the server refuses a zero lifetime with
  VALUE_OUT_OF_RANGE (#802).
