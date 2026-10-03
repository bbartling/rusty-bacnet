---
section: Fixed
---
- **Breaking (wire):** The trend pollers (Trend Log Multiple too) log a CharacterString, Double,
  array or other unlisted datatype as an any-value carrying its encoding instead of NULL (#1236).
