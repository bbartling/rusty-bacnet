---
section: Migration notes
---
- **Color and Color Temperature rows (wire, #1474):** Status_Flags,
  Event_State, Reliability and Out_Of_Service now answer UNKNOWN_PROPERTY, so
  a client that read or wrote them should stop, and a whole-object COV report
  carries Present_Value alone. Default_Fade_Time starts at 100 ms and refuses
  a value outside 100 to 86,400,000 ms.
