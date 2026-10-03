---
section: Fixed
---
- **Breaking (wire, Rust API):** when an object refuses an AddListElement that
  adds several elements, the ChangeList-Error names the refused element
  instead of the first new one (#1048).
