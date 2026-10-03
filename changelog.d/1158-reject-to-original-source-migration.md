---
section: Migration notes
commit: 83cb97e51059fa6961561e7cbd5832d0a8d4428d
---
- `NpduDecodeError::AddressTooLong` gained a `source` field; patterns that
  match the variant without `..` must name it (#1158).
