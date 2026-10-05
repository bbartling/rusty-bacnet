---
section: Migration notes
commit: df016bb551d99c88bd42b96cb6bca8ec75651045
---
- **Custom transports (Rust API, #693):** implement
  `local_receive_apdu_capacity()`, the largest APDU the link accepts, and
  rename `max_apdu_length()` to `egress_apdu_limit()`; a wrapping transport
  delegates both. A `ReceivedNpdu` literal sets
  `provenance: TransportProvenance::unverified()` and `direct_response: None`.
  See [local receive capacity](docs/rust-api.md#local-receive-capacity-and-outgoing-limits).
