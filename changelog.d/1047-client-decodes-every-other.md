---
section: Fixed
---
- **Breaking (Rust API):** the client decodes every Clause 21 structured error
  body, so a CreateObject, SubscribeCOVPropertyMultiple,
  ConfirmedPrivateTransfer or VTClose error returns its fields instead of
  timing out (#1047).
