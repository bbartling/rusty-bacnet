---
section: Added
---
- **Breaking (wire):** writing a Command object's Present_Value runs the
  Action list it selects through the local write path, tracking In_Process and
  All_Writes_Successful; a number past the Action size is refused (#1150).
