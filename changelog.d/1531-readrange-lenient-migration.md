---
section: Migration notes
---
- **ReadRange (Rust API, #1531):** a ReadRange answer that breaks a rule fails
  with `Error::ReadRangeViolation(rule)` instead of `Error::Decoding` at offset
  0; add an arm for it where you match `Error` exhaustively. On the endpoint,
  `EndpointReadRequest::Range` takes a `ReadRangeValidation`, and
  `EndpointReadAck::Range` and `into_range` carry a `ReadRangeReply`.
