---
section: Fixed
---
- Changes committed by background tasks now reach COV subscribers without waiting
  for an unrelated later write (#889). Before, periodic Time_Delay alarm
  confirmations, fault-detection reliability changes and schedule writes updated
  objects silently. A subscriber missed the IN_ALARM or FAULT Status_Flags change,
  or a scheduled Present_Value, until something else fanned COV out for that object.
  Each of these commits now fans COV out after its database guard is dropped, using
  the same post-write path as a network write, and records timestamped
  COV-multiple history at commit time. The bundled Event Enrollment objects accept
  no COV subscriptions, so their evaluation needs no fanout.
