---
section: Fixed
---
- Target Audit Reporters now support an optional object-owned
  Maximum_Send_Delay/Send_Now pair (#783). `None` keeps both absent; 0–3600 seconds
  exposes the pair, with zero immediate. The Rust aggregate configuration gains
  a sixth typed delay argument; Python dictionaries accept `maximum_send_delay`.
  Source Reporters reject the pair. Ordinary batching has global/per-Reporter
  record, byte and historical-context bounds; mandatory changes remain immediate.
  TRUE fences currently unsent work and FALSE means quiescent, not delivered.
  Target stop retains one three-second drain deadline across cancellation while
  allowing ACK/control progress. Historical loss summaries retain captured routes
  and original admission order; filtering remains an explicitly partial profile.
  See [delayed target Audit reporting](docs/delayed-target-audit.md).
