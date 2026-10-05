---
section: Migration notes
---
- **Audit Log persistence (Rust API, #1270):** custom Audit Log persistence
  runs on a plain `std` thread with no Tokio context, and a panic there fails
  the save.
