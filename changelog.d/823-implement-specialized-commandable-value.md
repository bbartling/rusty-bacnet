---
section: Fixed
---
- Implement specialized commandable Value_Source COV for AO/AV/BO/BV/MSO/MSV
  (#823). Single and Multiple reports capture PV, Status_Flags, Value_Source,
  Last_Command_Time and Current_Command_Priority together. Object PV criteria,
  flags, source and priority trigger reports; time alone does not. Failed
  companions preserve the baseline, healthy Multiple siblings proceed, and
  overlapping fields are deduplicated without completing unqualified references.
