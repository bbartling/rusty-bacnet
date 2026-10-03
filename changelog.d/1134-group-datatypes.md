---
section: Fixed
---
- **Breaking (wire, Rust API):** the Group object serves List_Of_Group_Members
  and Present_Value in their Table 12-17 datatypes, and rebuilds Present_Value
  from the members on every read (#1134).
