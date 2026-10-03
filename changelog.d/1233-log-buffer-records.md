---
section: Fixed
---
- **Breaking (wire):** ReadRange serves Trend Log and Event Log records framed as BACnetLogRecord and
  BACnetEventLogRecord, with encoders and decoders in `bacnet_encoding::constructed` (#1233).
