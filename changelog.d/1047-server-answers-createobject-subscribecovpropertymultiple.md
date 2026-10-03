---
section: Fixed
---
- **Breaking wire format:** the server answers CreateObject and
  SubscribeCOVPropertyMultiple errors with their Clause 21 bodies instead of a
  plain class and code (#1047). A CreateObject-Error carries the position,
  counted from 1, of the initial value that could not be applied, or 0 when the
  request or the object was refused (authorization, an identifier in use, an
  unsupported type, no space). An initial value that does not decode is now
  PROPERTY / INVALID_DATA_ENCODING at its position, where it was SERVICES /
  OTHER. A SubscribeCOVPropertyMultiple-Error names the monitored object and
  the property reference of a refused COV reference (unknown object, object or
  property without COV, unknown property, index on a property that is not an
  array, an oversized sample, no room left for it under the subscription caps
  since #1059); a failure before the references are processed (lifetime,
  notification delay, clock, authorization) is the general choice, the class
  and code alone. A peer that only parses the plain form no longer reads these
  errors. The server does not serve ConfirmedPrivateTransfer or VT-Close, which
  it still rejects.
