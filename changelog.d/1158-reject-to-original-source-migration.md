---
section: Migration notes
---
- `NpduDecodeError::AddressTooLong` gained a `source` field; patterns that
  match the variant without `..` must name it (#1158).
