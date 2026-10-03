---
section: Changed
commit: badb67cce780470d1b952503642ac2f1561bd288
---
- **Breaking (wire, Rust API):** an Access Door command outside the four
  BACnetDoorValue values, or a Credential_Status write other than INACTIVE or
  ACTIVE, fails with VALUE_OUT_OF_RANGE; the door stores `DoorValue` (#979).
