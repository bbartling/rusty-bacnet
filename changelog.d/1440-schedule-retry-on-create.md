---
section: Changed
---
- A Schedule whose reference was refused because the object it names didn't
  exist offers that object its value as soon as it is created, by CreateObject
  or a local `ObjectDatabase::add`, instead of at the next 60-second pass
  (#1440).
