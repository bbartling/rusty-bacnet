---
section: Fixed
---
- **Breaking `BACnetAddress` MAC bound (wire, Rust API):** every recipient,
  ValueSource and AuditLogQuery address codec now refuses a MAC longer than
  `BACnetAddress::MAX_MAC_LEN` (18 octets) in both directions, and the
  recipient encoders return `Result` (#1156).
