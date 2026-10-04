---
section: Added
---
- **Wire and Rust API:** CreateObject sets Units on Analog Input and Output,
  and Number_Of_States and State_Text on the multi-state objects, which stay
  read-only to WriteProperty; `pics::ObjectTypeSupport` gains
  `creation_only_properties`, so struct literals need it (#1429).
