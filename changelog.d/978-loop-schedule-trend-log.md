---
section: Fixed
---
- Loop, Schedule, Trend Log and Trend Log Multiple now compute Status_Flags
  as the other objects do (#978). They used to return the flags they were
  built with, so Status_Flags read all FALSE forever: a Loop or Schedule whose
  Reliability was evaluated or simulated as a fault still reported FAULT
  FALSE, and neither set OUT_OF_SERVICE when Out_Of_Service was TRUE. Loop and
  Schedule now derive FAULT from Reliability, OUT_OF_SERVICE from
  Out_Of_Service and IN_ALARM from Event_State. Trend Log and Trend Log
  Multiple derive only FAULT and IN_ALARM, and keep OVERRIDDEN and
  OUT_OF_SERVICE FALSE as their object types require; both have since lost
  their non-standard Out_Of_Service property (see the #985 entry). Calendar,
  which the standard gives no Status_Flags, no longer serves one (see the
  #984 entry below). A Loop's COV subscribers now get a notification when a
  write to Reliability or Out_Of_Service changes its Status_Flags, carrying the
  new flags; before, they never heard of either change.
