---
section: Fixed
---
- **Python API:** a local write such as `write_property_local` or `set_present_value_local` whose
  asyncio task is cancelled after the write committed still sends its COV and event notifications
  and runs the Command or Channel it started (#1367).
