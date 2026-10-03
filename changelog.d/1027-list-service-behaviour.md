---
section: Fixed
commit: d697b35ad304bb2c5eb3c0455054932a4d3119a1
---
- **Breaking (wire):** AddListElement leaves an element that is already
  present alone, and RemoveListElement refuses the whole request when an
  element is missing or of another datatype (#1027).
