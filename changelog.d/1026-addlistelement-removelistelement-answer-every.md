---
section: Fixed
---
- **Breaking wire format and Rust API:** AddListElement and RemoveListElement
  now answer every error with a ChangeList-Error, which carries the First
  Failed Element Number, instead of a plain class and code (#1026). The number
  is the position, counted from 1, of the request element that failed, or 0
  when the request or its target was refused (authorization, unknown object or
  property, array index, not a list, write access). A peer that only parses the
  plain form no longer reads these errors. The client decodes the new form, which
  it used to drop as undecodable, and returns `Error::Structured` with
  `ErrorDetail::FirstFailedElementNumber` (the variant #1047 generalized); a
  device that still sends only a class and code returns `Error::Protocol` as
  before. `bacnet_services::list_manipulation::ChangeListError` encodes and
  decodes the body. In Python, `BacnetProtocolError` gains
  `first_failed_element_number`, `None` for other errors.
