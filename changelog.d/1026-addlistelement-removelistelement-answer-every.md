---
section: Fixed
commit: d697b35ad304bb2c5eb3c0455054932a4d3119a1
---
- **Breaking (wire, Rust API):** AddListElement and RemoveListElement answer
  every error with a ChangeList-Error carrying the first failed element
  number, which the client returns as `Error::Structured` and Python as
  `first_failed_element_number` (#1026).
