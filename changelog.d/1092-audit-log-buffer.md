---
section: Changed
---
- **Breaking (wire):** Audit Log serves Log_Buffer through ReadRange by position, sequence or time, and
  ReadProperty answers it with READ_ACCESS_DENIED. ReadRange references and First Sequence Number are
  `u64` (#1092).
