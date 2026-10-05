---
section: Migration notes
---
- **Python typed constructed reads (#1345):** reads of the properties in
  [the typed constructed values table](docs/python-api.md#typed-constructed-values)
  return the forms it gives (mappings, tuples, `BACnetTimeStamp`) instead of
  octets, and no longer equal `PropertyValue.application_data` of them;
  writing a read value back sends the same octets.
