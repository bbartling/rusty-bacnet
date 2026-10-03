---
section: Migration notes
---
- **Credential Data Input (Rust API, #1249):**
  `CredentialDataInputObject::set_present_value` returns `Result` and refuses a
  factor whose format and class the reader does not declare (UNDEFINED and
  ERROR with class 0 excepted); call `set_supported_formats` first and handle
  the error. `set_supported_formats` now resets a Present_Value the new list
  doesn't cover to UNDEFINED.
