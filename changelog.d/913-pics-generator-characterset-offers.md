---
section: Fixed
---
- The PICS generator's `CharacterSet` now offers exactly the six character sets
  in Annex A's "Character Sets Supported" section, each printed with its Annex A
  label (#913). `DbcsMs` printed JIS C 6226, the old name of JIS X 0208, so it
  repeated `Jisx0208`. `Ansi` printed ANSI X3.4, which Annex A no longer offers
  and whose code now means UTF-8. Both are gone. `DbcsIbm` and `Jisx0208` become
  `IbmMicrosoftDbcs` and `JisX0208`, and the new `Ucs4` and `Ucs2` cover
  ISO 10646 UCS-4 and UCS-2. UTF-8 now prints as `ISO 10646 (UTF-8)`. Each
  variant's discriminant, also returned by `CharacterSet::code`, is its Clause
  20.2.9 code from `bacnet_encoding::primitives::charset`, and
  `CharacterSet::ALL` lists the six in code order.
