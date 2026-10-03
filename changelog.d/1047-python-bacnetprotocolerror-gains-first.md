---
section: Fixed
---
- Python's `BacnetProtocolError` gains `first_failed_write_attempt` and
  `first_failed_subscription` (object, property and index dicts, typed
  `ObjectPropertyReference` in the stub), `vendor_id`, `service_number`,
  `error_parameters` and `vt_session_identifiers` (#1047). Each is `None`
  unless the device's error carried it, on the class as well as on raised
  instances.
