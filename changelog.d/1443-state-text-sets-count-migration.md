---
section: Migration notes
---
- **Multi-state objects (Rust API, #1443):**
  `multistate::MAX_CREATED_NUMBER_OF_STATES` is now `MAX_NUMBER_OF_STATES`,
  and State_Text is no longer in `creation_only_properties`, since a write
  takes it whole. Number_Of_States rows carry the new
  `PropertyWriteCapability::Through(STATE_TEXT)`, which counts as writable.
