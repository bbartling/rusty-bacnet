---
section: Migration notes
---
- **Decoding errors (Rust API, #1446):** add `..` to patterns on
  `Error::Decoding { offset, message }`, or bind `kind`, and build one with
  `Error::decoding` or a kind's constructor (`invalid_tag`, `missing`,
  `trailing`, `out_of_range`, `overflow`) rather than a struct literal. Match
  `kind: DecodingKind::InvalidTag` where you matched `Error::InvalidTag`, and
  turn a request's decode error into its Reject with
  `Error::into_request_reject`.
