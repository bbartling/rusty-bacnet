---
section: Changed
---
- **Python API:** `BACnetServer` takes `mutation_policy="deny_all"` to refuse
  the ten network mutation services while reads and trusted local writes still
  work; the default stays permissive (#768).
