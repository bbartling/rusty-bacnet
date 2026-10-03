---
section: Migration notes
---
- **Parameter structs (Rust API, #902):** build
  `AnyTransport::Bip(Box::new(..))`, pass a `CovPropertySubscription` to
  `subscribe_cov_property`, a `RoutedTarget` to
  `send_apdu_routed_with_data_attributes` and a `WritePropertyRequest` to
  `ClientRoleHandle::write_property`, and replace the removed routed-read
  wrappers with `read_property_with_destination` and
  `EndpointApduDestination::Routed`.
