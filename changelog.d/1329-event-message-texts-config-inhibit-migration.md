---
section: Migration notes
---
- **Event_Algorithm_Inhibit (Rust API, #1329):** `BACnetObject` gains the
  hidden hooks `event_algorithm_inhibit_reference_internal` and
  `follow_event_algorithm_inhibit_internal`, and `ObjectDatabase` gains
  `follow_event_algorithm_inhibit`, which the bundled server calls before it
  evaluates an object. A wrapper object that forwards its hooks forwards
  both; a custom intrinsic reporter can serve the rows by answering them.
