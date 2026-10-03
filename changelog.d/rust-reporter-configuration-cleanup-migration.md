---
section: Migration notes
---
- **Audit Reporter hook (Rust API):** custom Reporters implement the
  five-setting `configure_audit_reporter_internal`. `None` selectors restore
  catch-all selection, and an empty vector selects no ordinary targets.
