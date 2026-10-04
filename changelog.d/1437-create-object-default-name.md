---
section: Fixed
---
- **Wire:** CreateObject no longer fails when another object holds the default
  name of the new one. That name is now the type and instance (`BINARY_VALUE-2`,
  not `ObjectType::BINARY_VALUE-2`), with the first free ` (n)` added when it
  is taken (#1437).
