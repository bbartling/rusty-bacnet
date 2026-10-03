---
section: Migration notes
---
- **VT, WriteGroup and device identity services (#912):** `VTOpenRequest`
  needs a local session ID and a `VTClass`, WriteGroup takes `u16` channels
  and a `NonZeroU32` group number, and `WhoAmIRequest` the vendor ID, model
  name and serial number. Python's `vt_open`, `write_group` and `who_am_i`
  take the same.
