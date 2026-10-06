---
section: Migration notes
---
- **Endpoint ReadRange (Rust API, #1531):** `EndpointReadRequest::Range`
  takes a `ReadRangeValidation`, and `EndpointReadAck::Range` and
  `into_range` carry a `ReadRangeReply`.
