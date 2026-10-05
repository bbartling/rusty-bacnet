---
section: Migration notes
---
- **Structured View (Rust API, #1285):**
  `StructuredViewObject::add_subordinate` returns `Result`, and the Structured
  View subordinate fields are private: replace them with `set_subordinates`
  and read them with `subordinates()`.
