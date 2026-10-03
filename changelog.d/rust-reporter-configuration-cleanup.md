---
section: Changed
---
- **Breaking (Rust API):** `BACnetObject::configure_audit_reporter_internal`
  takes all five Reporter settings at once, replacing the three-argument hook
  and `configure_audit_reporter_with_filters_internal`.
