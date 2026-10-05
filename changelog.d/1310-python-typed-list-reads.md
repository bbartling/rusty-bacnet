---
section: Changed
---
- **Breaking (Python API):** Recipient_List, a Group's members and
  Present_Value, a Command's Action and the other constructed lists the
  binding writes read as typed values. In 0.11.0 a local read gave the stored
  octets or flat list, and a client read only the first application-tagged
  value (#1310).
