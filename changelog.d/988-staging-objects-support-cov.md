---
section: Added
---
- Staging objects support COV (#988). A SubscribeCOV notification carries
  Present_Value, Status_Flags and Present_Stage, and goes out when
  Present_Value moves by at least COV_Increment, when Status_Flags changes, or
  when Present_Stage changes, as the COV criteria table (Clause 13.1, Table
  13-1) lists for Staging. Staging gains the COV_Increment property that table
  calls for: a writable REAL, default 0 (any change), where a negative or
  non-finite value fails with VALUE_OUT_OF_RANGE. SubscribeCOVProperty works
  for Present_Value (which inherits COV_Increment), Status_Flags and
  Present_Stage, each reported with Status_Flags. When a target plan's
  completion changes Reliability, subscribers get the Status_Flags change. A
  WriteProperty that changes the stage runs the stage's target writes before
  its own COV fanout, so one notification can carry both the new stage and
  the completion's flags; `write_local` reports the stage first. The new
  `BACnetObject::cov_reported_properties` hook, with `CovReportedProperty`,
  lists the values a SubscribeCOV notification carries after Present_Value and
  Status_Flags, and which of them also trigger one; the default follows the
  table for Loop and Staging, and the server leaves out any the object's
  Property_List lacks.
