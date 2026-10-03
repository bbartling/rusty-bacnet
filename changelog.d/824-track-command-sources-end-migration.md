---
section: Migration notes
---
- **Command sources (#824):** Rust local writes take a `LocalCommandSource`,
  and Python local writes the keyword `source_object`. `write_property_from`
  carries a network source, and the unsourced Analog Value setter is gone.
