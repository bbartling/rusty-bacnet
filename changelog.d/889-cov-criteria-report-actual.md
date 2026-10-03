---
section: Fixed
---
- COV criteria now report only an actual change (#889). A missing COV increment,
  or one of zero or less (the analog default is 0), means any change. Before,
  subscribers to binary, multi-state and zero-increment objects were re-sent the
  same value whenever the object was fanned out again, for example by a repeated
  write or a schedule write masked by a higher priority. A numeric Present_Value
  that is not Real, such as the Accumulator's Unsigned count, is now gated by its
  COV increment as the property path already was. Before, it reported on every
  fanout. Status_Flags changes and the first report after subscription still
  always notify.
