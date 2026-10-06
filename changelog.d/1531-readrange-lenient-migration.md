---
section: Migration notes
---
- **ReadRange (Rust API, #1531):** a ReadRange answer that breaks a rule fails
  with `Error::ReadRangeViolation(rule)`, not `Error::Decoding`; match it where
  you match `Error` exhaustively. Strict now also refuses pages it accepted,
  such as bacnet-stack 1.6.1's backward By-Position and By-Time pages (FIRST_ITEM
  with MORE_ITEMS); read such devices with `ReadRangeValidation::Lenient`.
