---
section: Changed
---
- **Breaking (wire, Rust API):** State_Text written whole on a multi-state
  object, by WriteProperty, WritePropertyMultiple or a CreateObject that
  gives no Number_Of_States, sets Number_Of_States to its number of labels,
  refusing a shrink that would strand a state the object holds (#1443).
