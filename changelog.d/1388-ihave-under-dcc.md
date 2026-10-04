---
section: Fixed
---
- **Breaking (wire, Rust API):** While DeviceCommunicationControl's
  DISABLE_INITIATION is in force, the server no longer answers Who-Has with
  I-Have, and `broadcast_i_am()` sends nothing and returns an error; Who-Is
  still gets its I-Am (#1388).
