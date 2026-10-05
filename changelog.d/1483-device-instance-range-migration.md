---
section: Migration notes
---
- **Who-Is and Who-Has ranges (Rust API, #1483):** write `range: None` or
  `range: Some(DeviceInstanceRange::new(low, high)?)` in `WhoIsRequest` and
  `WhoHasRequest`, and pass that one value to `BACnetClient::who_is`,
  `who_is_directed`, `who_is_network` and `who_has`.
  `DeviceInstanceRange::single(n)` asks one device, and
  `DeviceInstanceRange::from_limits` turns two optional limits into a range.
  Python callers pass both limits or neither.
