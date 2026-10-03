---
section: Fixed
---
- ReadRange on the Device's Active_COV_Subscriptions and
  Active_COV_Multiple_Subscriptions now pages the live subscriptions (#1046).
  A running server answered SERVICES / OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED,
  because ReadRange read the Device object's empty placeholder while
  ReadProperty read the server's COV table. ReadRange now reads through the
  same Device view as ReadProperty, samples the COV table once per request
  (after the database lock, in the server's lock order) and splits each list
  into its BACnetCOVSubscription or BACnetCOVMultipleSubscription elements.
  A page's items joined in order are a run of the ReadProperty value, also when
  the byte cap shortens the page, and subscriptions that change during a
  request don't tear it. The standalone `handle_read_range` pages the Device
  object's empty lists as no items, as standalone `handle_read_property` reads
  them. The new `bacnet_encoding::constructed::decode_cov_subscription` and
  `decode_cov_multiple_subscription` decode one element of each list.
