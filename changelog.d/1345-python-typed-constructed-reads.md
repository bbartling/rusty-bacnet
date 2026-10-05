---
section: Changed
---
- **Breaking (Python API):** Date_List, schedules, timestamps, Value_Source
  and the other constructed properties in
  [the Python API guide](docs/python-api.md#typed-constructed-values) read as
  typed values. In 0.11.0 a local read gave the stored octets or flat list,
  and a client read only the first application-tagged value (#1345).
