---
section: Fixed
---
- **Breaking Trend Log property set (wire):** Trend Log and Trend Log Multiple
  no longer serve Out_Of_Service (#985). Neither property table (Clause 12.25,
  Table 12-29; Clause 12.30, Table 12-35) defines it, yet Trend Log listed a
  writable one that changed nothing (#978 already kept it from the flags) and
  Trend Log Multiple a read-only one fixed at FALSE. It is gone from their
  Property_List, property metadata, RPM ALL and OPTIONAL, and PICS rows, and
  ReadProperty or WriteProperty on it now fails with PROPERTY /
  UNKNOWN_PROPERTY, as #984 did for Calendar.
