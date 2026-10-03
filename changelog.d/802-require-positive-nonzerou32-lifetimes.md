---
section: Fixed
---
- Require positive `NonZeroU32` lifetimes in Rust single-property COV subscribe
  methods; explicit cancellation remains separate. The request encoder is now
  fallible and transactional. Invalid incoming field pairs reject before state
  changes; paired zero lifetime returns SERVICES/VALUE_OUT_OF_RANGE (#802).
  Ordinary COV indefinite lifetimes and existing Python APIs are unchanged.
