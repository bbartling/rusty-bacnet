---
section: Added
---
- **Averaging samples and property COV (wire, breaking API):** a running
  server's application can now feed an Averaging object its samples (#1083).
  Before, only `AveragingObject::add_sample` could, and nothing reached the
  concrete type once the server held the object.
  - The server doesn't read Object_Property_Reference. The application
    samples that property and calls `BACnetServer::add_averaging_sample_local`
    (Python: `BACnetServer.add_averaging_sample_local`), which goes through the
    new `BACnetObject::add_averaging_sample_internal` hook. A BOOLEAN (counted
    as 0 or 1), Signed, Unsigned, Enumerated or finite REAL is accepted, as
    Clause 12.5 computes in REAL. Another datatype, Double included, fails with
    INVALID_DATA_TYPE, and NaN or an infinity with VALUE_OUT_OF_RANGE; a
    refused sample counts as neither attempted nor valid. An unknown object
    fails with UNKNOWN_OBJECT, and any object other than an Averaging object
    with OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED.
  - Minimum_Value, Maximum_Value, Average_Value, Attempted_Samples and
    Valid_Samples change together, then the server's COV path runs.
    SubscribeCOVProperty and SubscribeCOVPropertyMultiple on an Averaging
    object, which answered OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED, are now
    admitted and report by the Table 13-1a criteria, without Status_Flags
    since the object has none. SubscribeCOV stays refused, as Table 13-1 has
    no Averaging row. The new `BACnetObject::supports_subscribe_cov_property`
    (default: `supports_cov`) admits the property forms, and the default
    `supports_cov_property` now follows it.
  - `AveragingObject::add_sample` now returns `Result<(), Error>` and refuses
    NaN or an infinity, which used to corrupt the average for good.
