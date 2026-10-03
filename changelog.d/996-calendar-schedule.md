---
section: Fixed
commit: 107e9fa5fe54d0c990083ac264b833b06672833f
---
- **Breaking (wire, Rust API):** Calendar's Date_List and the Schedule's
  calendar entries, special events, daily schedules and Effective_Period use
  their Clause 21 encodings, and Date_List is network-writable (#996).
