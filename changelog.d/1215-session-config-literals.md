---
section: Migration notes
---
- Exhaustive Rust `bacnet_endpoint::session::SessionConfig` literals need the
  `read_work_limit` field added by #1215, or `..SessionConfig::default()`.
