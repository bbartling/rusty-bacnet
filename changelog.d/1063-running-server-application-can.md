---
section: Added
---
- A running server's application can now update a Loop's
  Controlled_Variable_Value (#1063). Before, only
  `LoopObject::set_controlled_variable_value` could set it, and nothing could
  reach a Loop's concrete type once the server held it. The application that
  runs the loop's algorithm calls
  `BACnetServer::set_controlled_variable_value_local` (Python:
  `BACnetServer.set_controlled_variable_value_local`), which goes through the
  new `BACnetObject::set_controlled_variable_value_internal` hook. It takes a
  finite REAL. Another datatype fails with INVALID_DATA_TYPE, and NaN or an
  infinity with VALUE_OUT_OF_RANGE. An unknown object fails with
  UNKNOWN_OBJECT, and any object other than a Loop with
  OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED, as with `set_present_value_local`.
  The route is accepted while Out_Of_Service is TRUE, which decouples only
  the output and Reliability. The change goes through the server's COV path:
  a SubscribeCOVProperty on Controlled_Variable_Value is notified. A
  SubscribeCOV on the Loop is not, since the COV criteria table (Clause 13.1,
  Table 13-1) carries the value without making it a trigger, so the next
  report carries the new value. The property stays read-only over the
  network. The server doesn't follow Controlled_Variable_Reference itself.
