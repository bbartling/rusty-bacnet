---
section: Fixed
---
- **Breaking Access Credential property set (wire):** the Access Credential no
  longer serves Present_Value (#979), so a client that read it now gets an
  error. Its property table (Clause 12.35, Table 12-40) has no Present_Value
  row. The property arrived with the 0.1.0 import, which described it as the
  credential's active or inactive state, but that is Credential_Status, and
  nothing kept the two in step; the property metadata then listed it as an
  optional writable row. It is gone from the Property_List, the property
  metadata, RPM ALL and OPTIONAL, and the PICS rows, and ReadProperty or
  WriteProperty on it fails with PROPERTY / UNKNOWN_PROPERTY. Read
  Credential_Status instead.
