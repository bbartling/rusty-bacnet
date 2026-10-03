---
section: Fixed
---
- NORMAL B/IP full servers and endpoints now own local Network Number discovery/learning, using only explicit registration for configured provenance. Selected Number/Quality readback follows configured-source precedence; unregistered owners start unknown. Control workers preserve APDU/Audit progress and join shutdown with socket/registration ownership. Multiport routing remains separate under #863 (#875).
