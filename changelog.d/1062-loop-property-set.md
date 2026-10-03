---
section: Fixed
---
- **Breaking Loop property set (wire):** the Loop now serves the three rows
  its property table (Clause 12.17, Table 12-20) requires and it left out:
  Controlled_Variable_Units, Action and Priority_For_Writing (#1062). It also
  serves Proportional_Constant_Units, Integral_Constant_Units and
  Derivative_Constant_Units, which the table requires alongside the gain
  constants the Loop already served. Action is a writable BACnetAction,
  DIRECT (0) until written; a write other than DIRECT or REVERSE (1) fails
  with VALUE_OUT_OF_RANGE and leaves it as it was. The four units rows
  (NO_UNITS until set) and Priority_For_Writing (16 until set) are read-only
  over the network. The application sets them before adding the Loop with
  the new `LoopObject` setters, which refuse units above 65535 or a priority
  outside 1 to 16 with VALUE_OUT_OF_RANGE. The new rows appear in
  Property_List, the property metadata, RPM ALL, REQUIRED and OPTIONAL, and
  the PICS, and Property_List now lists the Loop's rows in the table's order.
  A Loop's Action is a single value, so an array index on it fails with
  PROPERTY_IS_NOT_AN_ARRAY; Command's Action array still takes one. The Loop
  doesn't run its control algorithm or command the property its
  Manipulated_Variable_Reference names, so Action and Priority_For_Writing
  describe the application's algorithm and change nothing in the object.
  Python's `add_loop` takes the read-only rows as keyword-only arguments
  (`controlled_variable_units`, `proportional_constant_units`,
  `integral_constant_units`, `derivative_constant_units`,
  `priority_for_writing`), checked like the Rust setters; omitted ones keep
  the defaults.
