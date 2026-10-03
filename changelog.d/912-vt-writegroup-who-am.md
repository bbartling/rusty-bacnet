---
section: Fixed
commit: 5ffc8a1a00c718762246839cba088b8c813d7f6e
---
- **Breaking (wire, Rust and Python API):** the Who-Am-I, You-Are, VT and
  WriteGroup codecs encode as the Clause 21 grammar does, so conformant peers
  can decode them, and their request types change to match (#912).
