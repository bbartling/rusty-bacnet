---
section: Changed
commit: df016bb551d99c88bd42b96cb6bca8ec75651045
---
- **Breaking (Rust API):** a custom `TransportPort` must provide
  `local_receive_apdu_capacity()`, `max_apdu_length()` is renamed
  `egress_apdu_limit()` with no alias, and `ReceivedNpdu` gains `provenance`
  and `direct_response` (#693).
