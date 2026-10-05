---
section: Changed
---
- **Rust API:** Under a `mutation_authorizer`, WritePropertyMultiple attempts that objects save
  first are decided before their save is staged, so it runs with the database guard released;
  the authorizer may be asked about such an attempt the request never reaches (#1321).
