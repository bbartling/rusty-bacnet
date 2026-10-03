---
section: Fixed
---
- Eligible AV/BV Audit policy changes now reserve their immediate notification
  before committing through network WP/WPM and `BACnetServer::write_local` (#809).
  Unavailable route, runtime, capacity, confirmed lease or APDU fit returns
  SERVICES/SERVICE_REQUEST_DENIED without changing the policy or consuming an
  event sequence. This is a local admission policy; ordinary writes remain
  best-effort and successful delivery is not guaranteed.
