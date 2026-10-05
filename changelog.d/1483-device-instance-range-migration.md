---
section: Migration notes
---
- **Who-Is and Who-Has ranges (Rust API, #1483):** `WhoIsRequest::range(low,
  high)` is gone. Write `range: None` or
  `range: Some(DeviceInstanceRange::new(low, high)?)` in `WhoIsRequest` and
  `WhoHasRequest`, and pass that one value to `BACnetClient::who_is`,
  `who_is_directed`, `who_is_network` and `who_has`. `single(n)` and
  `from_limits` return a `Result`; `device(oid)` cannot fail. Python callers
  pass both limits or neither.
