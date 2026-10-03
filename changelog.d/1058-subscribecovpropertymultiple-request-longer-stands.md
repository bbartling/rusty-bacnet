---
section: Fixed
commit: 73a3b28ada3d2729431d0dcb7804a8ca3d417677
---
- **Breaking (wire, Rust API):** SubscribeCOVPropertyMultiple processes its
  references in order and stops at the first failure, keeping the ones before
  it; the subscription caps are checked per reference too (#1058, #1059).
