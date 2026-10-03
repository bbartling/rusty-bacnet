---
section: Fixed
---
- A full server's shutdown retires I-Am admission, joins admitted sends and
  stops its own transport, so a retained broadcaster handle no longer keeps
  the socket alive (#872).
