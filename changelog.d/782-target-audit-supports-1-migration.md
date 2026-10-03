---
section: Migration notes
---
- **Audit Reporters (#782, #783):** replace the singular Reporter selectors
  with `AuditReportersConfig { reporters }` and `.audit_reporters(...)` in
  Rust, or `configure_audit_reporters([...])` in Python. Each Rust Reporter
  configuration also takes the optional send delay; pass `None` to leave
  Maximum_Send_Delay and Send_Now absent.
