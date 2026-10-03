---
section: Fixed
---
- **COV-multiple history bound (wire behaviour):** a change going out one
  value per notification is no longer evicted, so a value held back by a
  failed send or a confirmed deferral still goes out after a newer change
  (#1163).
