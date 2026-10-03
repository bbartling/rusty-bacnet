---
section: Fixed
commit: f04e5e1434bcf0f4400ba35cf5b939816d9d986b
---
- **Breaking (wire):** the Loop serves the required rows it left out:
  Controlled_Variable_Units, Action, Priority_For_Writing and the three
  gain-constant units. Python's `add_loop` takes them as keywords (#1062).
