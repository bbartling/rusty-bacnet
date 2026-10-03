---
section: Fixed
---
- Order Python B/IP, SC and MS/TP endpoint startup and close through one private
  owner (#861). Close cancels safe connection preparation and joins admitted
  session startup/teardown; cancelled waiters retain cleanup ownership. Competing
  starts cannot replace a live session or open a second transport. Registrations
  are sealed at admission and restored after failed/cancelled startup cleanup.
  TLS/serial setup errors now arrive when awaiting startup; explicit second-start
  errors and context reentry remain. The nine lifecycle methods now yield actual
  Python `None` as their `Awaitable[None]` stubs declare.
