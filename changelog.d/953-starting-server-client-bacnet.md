---
section: Fixed
commit: 943cc2071b05b7942c63d4cb9849db564bf3a353
---
- Starting a server, client or SC connection, and running the CLI, take much
  less stack in a debug build, and the native jobs now test with 1 MiB thread
  stacks (#953).
