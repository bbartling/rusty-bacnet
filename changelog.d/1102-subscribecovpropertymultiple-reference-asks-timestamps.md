---
section: Fixed
---
- **Breaking wire behaviour:** a SubscribeCOVPropertyMultiple reference that
  asks for timestamps while the Device has no valid clock is now refused on
  its own, in request order like any other failed reference (#1102). The
  error names it in the failed-subscription choice, still SERVICES /
  OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED, and the references before it stay
  subscribed and get their initial notification; those after it are not
  processed. Before, any timestamped reference refused the whole request with
  the general choice, even after references that would have been accepted.
  Timestamped is an option of each reference, and Clause 13.16.2 keeps the
  general error for failures before any reference is processed.
