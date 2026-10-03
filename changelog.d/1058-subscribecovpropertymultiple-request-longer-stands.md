---
section: Fixed
---
- **Breaking wire behaviour and Rust API:** a SubscribeCOVPropertyMultiple
  request no longer stands or falls as a whole (#1058). The server goes
  through its COV references in request order and stops at the first one that
  fails: the error names it, the references before it stay subscribed and get
  their initial notification, and the context's lifetime, notification delay
  and route are renewed as for an accepted request. The references after the
  failed one are not processed. Before, one refused reference left the whole
  request without effect. A request that fails at its first reference, or
  before any reference (inconsistent or out-of-range lifetime and delay,
  authorization), still changes and reports nothing (Clause 13.16.2). The
  subscription caps are checked one reference at a time as well (#1059). A
  renewal or a repeat of an earlier reference takes no slot, and the first
  reference that would go past the recipient's quota or the table's capacity
  is named in a RESOURCES / NO_SPACE_TO_ADD_LIST_ELEMENT failed-subscription
  error; the whole request used to go out with the general choice.
  `CovSubscriptionTable::subscribe_multiple` now fails with `MultipleRefusal`,
  which carries the error, the position of the refused reference and the
  snapshots kept before it.
