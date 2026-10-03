---
section: Fixed
commit: c88f61afece69424171fc35e970b7aefaf6703d8
---
- The Lift's Car_Door_Status and Landing_Door_Status accept writes while
  Out_Of_Service is TRUE, so a test tool can simulate the car; the door count
  stays the application's (#1035).
