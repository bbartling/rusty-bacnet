---
section: Changed
---
- Long parameter lists became parameter structs. `bacnet-client`'s
  `subscribe_cov_property` and `subscribe_cov_property_to_device` now take a
  destination and a `CovPropertySubscription`. `bacnet-network`'s
  `send_apdu_routed_with_data_attributes` now takes a
  `RoutedTarget { network, mac, router_mac }`. Three helpers without production
  callers were removed: `ReceivedApdu::unverified` (build the struct instead),
  and the `read_property_routed` wrappers on `bacnet-endpoint`'s
  `ClientRoleHandle` and on `bacnet-client`'s `EndpointRequester`, where it was
  hidden. Call `read_property_with_destination` with
  `EndpointApduDestination::Routed` instead; `bacnet_endpoint` now re-exports
  that type, so callers don't need `bacnet-endpoint-core` as a direct dependency.
  `BACnetClient::read_property_routed` is unchanged (#902).
