---
section: Fixed
---
- **Wire:** B/IP drops a datagram whose UDP source is a group address before
  handling its BVLC function, so a BBMD neither registers nor forwards from
  one, and counts it in the new `BipTransport::group_source_drops()` (#1504).
