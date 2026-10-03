---
section: Fixed
---
- **Breaking (wire, Rust API):** SubscribeCOVPropertyMultiple processes its
  references in order and stops at the first failure, keeping the ones before
  it; the subscription caps are checked per reference too (#1058, #1059).
