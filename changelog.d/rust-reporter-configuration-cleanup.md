---
section: Changed
---
- **Breaking Rust Reporter configuration cleanup (pre-1.0):**
  `BACnetObject::configure_audit_reporter_internal` now takes all five settings:
  audit level, operation flags, confirmed notifications, optional monitored-object
  selectors, and priority filter. The three-argument hook and the separate
  `configure_audit_reporter_with_filters_internal` name are removed. Custom Reporter
  implementations must implement the complete atomic contract; default trait
  implementations reject configuration. `None` selectors remove Monitored_Objects
  and restore catch-all selection, while an empty vector selects no ordinary
  targets. The endpoint's private source adapter forwards the complete contract.
  The Python configuration API and Reporter operational behavior are unchanged.
