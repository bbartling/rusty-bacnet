---
section: Changed
---
- `BACnetServer::stop()`'s docs say that a request already running when it
  begins can still make its write, unanswered, and that storage then keeps
  what the object serves (#1457).
