---
section: Fixed
---
- **Breaking (wire):** Access User Credentials reads as a list of device
  object references instead of bare object identifiers, so it can name a
  credential held by another device (#1394).
