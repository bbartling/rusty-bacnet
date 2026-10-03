---
section: Fixed
---
- Owned finite COV notifications no longer round a live subsecond remainder to
  indefinite zero (#819). One supplied-time projection rounds positive finite
  durations upward and saturates the wire range, keeping expiry distinct.
  Initial and later Single/Multiple sends resolve current snapshot ownership and
  live expiry after property reads; context-only renewal updates the projected
  deadline. Multiple discards stale values and their companions independently.
  Already admitted confirmed retries and ACK handling remain unchanged.
