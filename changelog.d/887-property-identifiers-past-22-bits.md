---
section: Fixed
---
- **Breaking (Rust API):** A Group member and an Event Enrollment reference may
  name a property identifier above 4194303, where ASHRAE assigns some, such as
  Default_Color; Group members naming one were refused (#887).
