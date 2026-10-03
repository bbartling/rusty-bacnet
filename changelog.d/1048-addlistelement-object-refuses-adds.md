---
section: Fixed
---
- **Breaking Rust API (wire behaviour for AddListElement):** when an object
  refuses an AddListElement that adds several new elements, the
  ChangeList-Error now names the element it refused (#1048). The object
  judges the edited list, its stored elements followed by the new ones in
  request order, and can name the element it refuses: `write_property`
  returns `Error::Structured` with `ErrorDetail::FirstFailedElementNumber`
  holding that element's position in the list, and the handler reports the
  request element at that position. Before, it reported the first element the
  list would gain, exact only when one element was new, and passed a position
  an object named through unchanged. The Multi-state Input and Value
  Alarm_Values, Lift and Escalator Fault_Signals and Calendar Date_List
  writers now name the element behind a datatype, encoding, range or space
  refusal, so for those refusals the Rust results of WriteProperty,
  WritePropertyMultiple and `write_local` are `Error::Structured` where they
  were `Error::Protocol` (match both for the class and code), and Python's
  `BacnetProtocolError` from `write_local` carries `first_failed_element_number`.
  WriteProperty and WritePropertyMultiple errors on the wire are unchanged.
  If an object names an element the list already held, or refuses what a
  removal leaves, the element number is 0. A refusal that names no element
  keeps the first-new-element estimate.
