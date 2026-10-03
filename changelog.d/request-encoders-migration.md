---
section: Migration notes
---
- **Request encoders (Rust API, #771, #780, #793, #798, #805, #808):** the
  ReadRange, ReadPropertyMultiple, WriteProperty, WritePropertyMultiple,
  AddListElement, RemoveListElement, SubscribeCOV and
  SubscribeCOVPropertyMultiple request encoders return `Result`; handle the
  error where you call one directly.
