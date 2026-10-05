---
section: Migration notes
---
- **Parameter structs (Rust API, #902):** build
  `AnyTransport::Bip(Box::new(..))`, pass a `CovPropertySubscription` to
  `subscribe_cov_property` and a `RoutedTarget` to
  `send_apdu_routed_with_data_attributes`.
