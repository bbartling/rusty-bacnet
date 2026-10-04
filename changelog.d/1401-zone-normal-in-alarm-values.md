---
section: Fixed
---
- **Breaking (wire, Rust API):** Access Zone refuses NORMAL in Alarm_Values, as
  the Access Door does in its alarm lists, since alarming on NORMAL would put a
  zone in alarm while its count sits inside its limits (#1401).
