---
section: Fixed
---
- An AddListElement or RemoveListElement that moves an object into or out of
  alarm, such as an Alarm_Values edit, starts the transition at once, as
  WriteProperty does, instead of at the next periodic tick (#1305).
