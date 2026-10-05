---
section: Migration notes
---
- **Colour property identifiers (#887, Rust and Python API):** the
  `PropertyIdentifier` constants `DEFAULT_COLOR`, `DEFAULT_COLOR_TEMPERATURE` and
  `COLOR_COMMAND` keep their names but change value, to 4194330, 4194331 and 4194334
  (in Python, `PropertyIdentifier.COLOR_COMMAND.to_raw()` was 508). Use the
  constants, not 508 to 510, which name Network Port properties. Drop any match on
  `GroupMemberRefusal::PropertyOutOfRange`, which is gone.
