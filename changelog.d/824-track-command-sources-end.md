---
section: Fixed
---
- Track command sources end to end for Analog Output/Value, Binary Output/Value
  and Multi-state Output/Value (#824). Object-owned state retains original
  correction owners, typed current/per-priority sources, and a wrapping sequence
  timestamp for effective command changes. Network, local, Schedule, Staging and
  CreateObject commands carry real origins; corrections accept valid claims only
  from the original owner. Pre-1.0 API changes add `write_property_from`, require
  `LocalCommandSource` on Rust local writes and keyword `source_object` on Python
  local writes, and remove the unsourced Analog Value setter. Context-free tracked
  writes fail closed. Specialized source-property COV is described above.
