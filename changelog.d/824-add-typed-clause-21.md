---
section: Fixed
---
- Add the typed Clause 21 ValueSource CHOICE codec as a prerequisite for #824.
  `BACnetValueSource::Object` now carries `BACnetDeviceObjectReference`, retaining
  the optional device qualifier. `encode_value_source` and `decode_value_source`
  handle none, object and address alternatives; decoding consumes one choice
  and returns the next offset. This pre-1.0 type change adds no source producer,
  Value_Source property-array behavior, correction authorization or Python API.
  The end-to-end #824 producer is described above; specialized COV #823 is described above.
