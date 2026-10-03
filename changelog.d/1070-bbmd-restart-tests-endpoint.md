---
section: Changed
---
- Test-only: the BBMD restart tests, and the endpoint and benchmarks tests that
  bind a stopped node's address to prove it was released, run again on fresh
  ports when another socket takes the port between the stop and the bind. A
  node that really keeps its port fails every run. A restart rebinds a port the
  OS chose, without SO_REUSEADDR, and every OS refuses that bind while another
  socket holds the port, so the macOS limit of the BBMD probe retry does not
  apply to it (#1070).
