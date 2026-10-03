---
section: Fixed
---
- Make full-server shutdown retire exported I-Am admission, join admitted sends,
  and stop its owned transport (#872). Retained broadcaster handles no longer
  keep sockets alive; local broadcasts have a shared 32-operation bound. Stop
  cancellation retains cleanup ownership, including the Python server wrapper;
  transport errors permit retry. Local mutations and broadcasts reject once
  shutdown starts; Rust local reads remain available.
