---
section: Fixed
---
- **Breaking (Python API):** read results keep every element of a value. A whole
  array or list reads as a `list` at any length, several values as a `list`, and
  context-tagged or otherwise unrepresentable content as `application_data`
  octets; only broken framing raises (#1296).
