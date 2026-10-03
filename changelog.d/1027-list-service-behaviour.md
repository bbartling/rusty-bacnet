---
section: Fixed
---
- **Breaking (wire):** AddListElement leaves an element that is already
  present alone, and RemoveListElement refuses the whole request when an
  element is missing or of another datatype (#1027).
