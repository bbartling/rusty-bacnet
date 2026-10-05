---
section: Migration notes
---
- **Answer matching (Rust API, #1465):** `CanonicalPeer::from_source` takes the
  known local network number as a third argument (`None` keeps the old
  matching).
