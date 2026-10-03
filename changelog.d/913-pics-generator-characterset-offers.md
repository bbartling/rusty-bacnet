---
section: Fixed
---
- **Breaking (Rust API):** the PICS generator's `CharacterSet` offers exactly
  Annex A's six character sets with their Annex A labels: `DbcsMs` and `Ansi`
  are gone, and `DbcsIbm` and `Jisx0208` become `IbmMicrosoftDbcs` and
  `JisX0208` (#913).
