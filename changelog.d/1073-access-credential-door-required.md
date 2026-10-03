---
section: Changed
---
- **Breaking (wire, Rust API):** Access Credential and Access Door serve every
  required row of their tables. Credential_Status is derived from
  Reason_For_Disable, and a pulse unlock command relinquishes after its pulse
  time (#1073).
