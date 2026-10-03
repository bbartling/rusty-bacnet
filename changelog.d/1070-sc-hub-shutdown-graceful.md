---
section: Changed
commit: 499dd0c803eb2e075ad7c2ecf429153cf35297c8
---
- Test-only: the SC hub shutdown and B/IP restart tests rerun on fresh ports
  the same way, through test-only `port_ownership` helpers shared in
  `bacnet-transport` (#1070, #1095).
