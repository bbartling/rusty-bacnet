---
section: Migration notes
---
- **Access Point (Rust API, #1325):**
  `set_number_of_authentication_policies` no longer refuses a count below
  Active_Authentication_Policy: it drops the active policy to 0, and the
  point reports CONFIGURATION_ERROR until a client writes a usable policy.
  Code that relied on the refusal should compare the count with the active
  policy first.
