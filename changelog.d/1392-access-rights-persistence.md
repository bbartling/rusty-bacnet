---
section: Added
---
- **Breaking (Rust API):** Access Rights can keep the rule arrays and Enable that peers write
  across a restart: `AccessRightsObject::with_persistence` with `FileAccessRightsPersistence`,
  or `storage_path` on Python's `add_access_rights`. `AccessRightsObject` is no longer
  `UnwindSafe` (#1392).
