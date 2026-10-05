---
section: Changed
---
- **Breaking (wire, Rust API):** State_Text written whole on a multi-state
  object, by WriteProperty, WritePropertyMultiple or a CreateObject without
  Number_Of_States, or its size at index 0, sets Number_Of_States, refusing
  a shrink that would strand a state the object holds (#1443).
