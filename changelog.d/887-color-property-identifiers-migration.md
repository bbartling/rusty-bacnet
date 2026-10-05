---
section: Migration notes
---
- **Colour property identifiers (#887):** `PropertyIdentifier::DEFAULT_COLOR`,
  `DEFAULT_COLOR_TEMPERATURE` and `COLOR_COMMAND` keep their names but are now
  4194330, 4194331 and 4194334; use the constants rather than 508 to 510, which are
  `ADDITIONAL_REFERENCE_PORTS`, `CERTIFICATE_SIGNING_REQUEST_FILE` and
  `COMMAND_VALIDATION_RESULT` (511 is `ISSUER_CERTIFICATE_FILES`). Drop any match on
  `GroupMemberRefusal::PropertyOutOfRange`, which is gone.
