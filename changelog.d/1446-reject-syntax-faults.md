---
section: Fixed
---
- **Wire:** the server rejects a confirmed request it can't decode with the
  reason naming the fault (TOO_MANY_ARGUMENTS, INVALID_TAG,
  MISSING_REQUIRED_PARAMETER or OTHER), formal-error services included, where
  it answered SERVICES / OTHER; the client's notification rejects agree
  (#1446).
