---
section: Migration notes
---
- **Python typed constructed reads (#1345):** reads of the properties in
  [the typed constructed values table](docs/python-api.md#typed-constructed-values)
  return the forms it gives (mappings, tuples, `BACnetTimeStamp`) instead of
  0.11.0's octets or flat lists, so a read that gave
  `PropertyValue.application_data` no longer equals it; writing a read value
  back sends the same octets.
