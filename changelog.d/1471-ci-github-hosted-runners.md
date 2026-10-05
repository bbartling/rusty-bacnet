---
section: Changed
---
- Issues, pull requests and CI moved from a private Forgejo to GitHub, keeping
  every issue number (#1472). Linux CI runs on GitHub-hosted runners, a PR
  merges only when its `CI OK` and `Native OK` checks pass, and runs on dev
  prune superseded Actions caches (#1471).
