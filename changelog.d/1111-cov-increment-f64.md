---
section: Migration notes
---
- **`BACnetObject::cov_increment` returns `Option<f64>` (#1111):** an object
  that overrides it changes the signature and returns
  `Some(f64::from(increment))`; `CovSubscriptionTable::should_notify` takes
  an `Option<f64>` increment too.
