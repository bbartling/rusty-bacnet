---
section: Changed
---
- **One LifeSafetyOperation outcome contract (Refs #752, pre-1.0 API break):**
  `BACnetObject::apply_life_safety_operation` now returns
  `LifeSafetyOperationOutcome`, containing the effect and ordered exact property
  deltas. The `_detailed` hook and empty-delta compatibility adapter are removed.
  Custom implementations report their own committed changes for COV; unsupported
  objects explicitly error. Built-in reset/arming, error atomicity and existing
  COV behavior are preserved. The unused public coarse server handler is also
  removed; confirmed dispatch uses one internal handler retaining exact COV changes.
