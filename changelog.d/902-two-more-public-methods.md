---
section: Changed
---
- Two more public methods take structs instead of long argument lists.
  `bacnet-endpoint`'s `ClientRoleHandle::write_property` now takes the
  destination MAC, a `bacnet_services::write_property::WritePropertyRequest` and
  the `Commandability`. `bacnet-network`'s
  `NetworkLayer::send_response_apdu_on_issuance` now takes a
  `bacnet_network::layer::IssuedApdu` (APDU, next hop, optional routed
  destination, expecting-reply flag, priority), the route and the issuance
  callback (#902).
