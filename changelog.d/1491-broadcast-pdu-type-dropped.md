---
section: Fixed
---
- **Wire:** `BACnetRouter` neither forwards nor delivers a remote or global
  broadcast whose APDU isn't an Unconfirmed-Request, and `NetworkLayer` doesn't
  deliver one; both count it in the new `broadcast_pdu_type_drops()` (#1491).
