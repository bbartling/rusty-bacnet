---
section: Fixed
---
- **Breaking (wire, Rust API):** `YouAreRequest` refuses a device MAC address
  longer than 18 octets on decode and encode (#1200).
