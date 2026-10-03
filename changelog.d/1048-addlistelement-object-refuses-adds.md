---
section: Fixed
commit: 436dd01dd5ff577d5cccf2a15e0ca91639969a94
---
- **Breaking (wire, Rust API):** when an object refuses an AddListElement that
  adds several elements, the ChangeList-Error names the refused element
  instead of the first new one (#1048).
