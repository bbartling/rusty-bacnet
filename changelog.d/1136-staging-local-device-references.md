---
section: Added
---
- **Staging targets naming this device (wire):** a Staging Target_References
  element whose Device identifier is the server's own Device is now accepted
  (#1136). Clause 12.62.14, like 12.24.10 for the Schedule, lets an object
  limited to its own device refuse only references outside it. The server
  stores such an element, through WriteProperty and WritePropertyMultiple
  (whole or by index) and `write_local`, as the local reference it stands
  for; it reads back without the Device member, and the current stage is
  applied to it at once. An element naming any other device is still
  OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED, and a `StagingObject` written directly
  or built from `StagingConfig` still refuses every Device member. The
  Schedule's rewrite (#1122) now lives in a shared module that handles both
  reference types.
