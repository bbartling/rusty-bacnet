---
section: Fixed
---
- **Breaking (wire):** the Loop's three references and Pulse Converter Input_Reference
  are served and written in their context-tagged forms, refusing the old flat list, and
  Averaging treats a reference that doesn't open with tag [0] as the wrong datatype (#1312).
