---
section: Changed
---
- The memory ceiling of a timestamped COV-multiple context's history counts the bytes each
  pending change really takes instead of a guessed 32 octets per change; a context keeps about
  the history it did, and the documented worst case is about 24 MB under the default caps (#1357).
