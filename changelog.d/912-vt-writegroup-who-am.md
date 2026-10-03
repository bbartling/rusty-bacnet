---
section: Fixed
---
- **Breaking (wire, Rust and Python API):** the Who-Am-I, You-Are, VT and
  WriteGroup codecs encode as the Clause 21 grammar does, so conformant peers
  can decode them, and their request types change to match (#912).
