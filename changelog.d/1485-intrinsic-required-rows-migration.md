---
section: Migration notes
---
- **Property metadata (Rust API, #1485):**
  `PropertyPresenceCondition::IntrinsicReporting` is split into
  `IntrinsicReportingRequired`, which `PropertyMetadata::is_required` counts,
  and `IntrinsicReportingOptional`; a custom object's rows pick the one its
  table's footnotes give.
