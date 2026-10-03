---
section: Fixed
---
- **Breaking (wire, Rust API):** AddListElement and RemoveListElement answer
  every error with a ChangeList-Error carrying the first failed element
  number, which the client returns as `Error::Structured` and Python as
  `first_failed_element_number` (#1026).
