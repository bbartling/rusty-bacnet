---
section: Migration notes
---
- **Decoding errors (Rust API, #1446):** add `..` to patterns on
  `Error::Decoding { offset, message }`, or bind `kind`, and build one with
  `Error::decoding`, `invalid_tag`, `missing` or `trailing` rather than a
  struct literal. Match `Error::Decoding { kind: DecodingKind::InvalidTag, .. }`
  where you matched `Error::InvalidTag`. A responder turns a request's decode
  error into its Reject with `Error::into_request_reject`.
