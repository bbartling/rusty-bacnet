---
section: Added
commit: 5e884c58d099ec9a910f1d8df23c985594217f88
---
- **Wire:** a Schedule accepts writes of Weekly_Schedule, Exception_Schedule
  and Effective_Period and applies them at once, and reports
  CONFIGURATION_ERROR while its values mix datatypes (#1057, #1056).
