---
section: Fixed
---
- **Wire:** Linux Ethernet drops a frame whose source MAC is a group address
  before answering an XID or TEST command or decoding it, and counts it in the
  new `EthernetTransport::group_source_drops()` (#1492).
