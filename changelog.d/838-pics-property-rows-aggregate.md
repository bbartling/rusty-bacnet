---
section: Fixed
---
- PICS property rows now aggregate every configured instance of each object type
  (#838), including mixed stream/record and read-only File objects. Presence and
  read/write capabilities are unions; required declarations win over optional
  ones. All rows sort by property ID, including single-instance output. Text and
  Markdown explain that availability and access depend on the concrete object.
  Served Device rows retain the executor-owned view before aggregation.
