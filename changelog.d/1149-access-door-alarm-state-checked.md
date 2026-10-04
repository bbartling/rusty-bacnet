---
section: Changed
---
- **Breaking (wire, Rust API):** Access Door keeps Door_Alarm_State to NORMAL and its
  alarm and fault values, outside its masked values, refusing other states from
  the application and from clients (#1149).
