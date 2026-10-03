---
section: Fixed
---
- **Breaking (Python API):** a Python process no longer crashes at exit while
  a Tokio thread completes an awaited future. The bindings bridge Tokio to
  asyncio themselves instead of through `pyo3-async-runtimes` (#1002).
