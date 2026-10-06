---
section: Changed
---
- A running server shares one copy of its configuration with request dispatch, local writes, Command
  and Channel runs and its background tasks, rather than copying it for each local write (#1521).
