---
section: Fixed
---
- **Breaking (wire):** a Who-Has carrying only one of its two limits, or a
  low limit above the high one, is malformed: `WhoHasRequest::decode` refuses
  it and the server drops it unanswered, as it does such a Who-Is (#1483).
