---
section: Fixed
commit: 0f43456afa2ae49d066aa2875d2db1524e0e4966
---
- **Breaking (Rust API):** the client decodes every Clause 21 structured error
  body, so a CreateObject, SubscribeCOVPropertyMultiple,
  ConfirmedPrivateTransfer or VTClose error returns its fields instead of
  timing out (#1047).
