# Rusty BACnet agent guidance

This repository uses focused skills and subagents for research and review. Prefer the installed skills under `.agents/skills/` and custom agents under `.codex/agents/`.

Use local Codebase Memory as the first structural code-intelligence layer. The canonical project is `Users-justin-Development-rusty-bacnet`, rooted at `/Users/justin/Development/rusty-bacnet`; verify it with `list_projects` and `index_status` when entering a fresh repository context, then use focused graph tools and check coverage for cited scopes. Codebase Memory is not a durable work ledger. Long-running compliance continuity lives in the ignored `_spec/rusty-bacnet-compliance-execution-plan/{Handoff.md,CURRENT_STATUS.md,NEXT_HANDOFF.md}` documents, with `codex-overnight-status.md` retained as an additional local historical log. Refresh live Git/GitHub state before acting on those snapshots. No external memory service, agent identity, namespace, or team assertion is a prerequisite.

Default behavior:

- Use read-only exploration first.
- Spawn subagents only for complex, parallel, or verification-heavy work.
- Keep subagent prompts scoped and evidence-led.
- Treat a READY review as final for that head SHA. If the head changes, rerun only review lanes affected by the new diff.
- Synthesize findings into a single decision or plan.
- Record commands, files, symbols, and sources used as evidence.
- Keep PRs small: one BACnet layer, state-machine family, or measured hotspot per PR.
- Do not add new CI unless explicitly requested.
- Do not broaden README or public support claims without conformance ledger rows, tests, and evidence.
- Treat `_spec/rusty_bacnet_compliance_specs_v1/` as the active compliance work plan and `_spec/2020_ASHRAE_Standard-135-BACnet-Data-Communication-Protocol.pdf` as the local Standard 135-2020 reference.

Recommended skills:

- `$codebase-research-pass`
- `$external-source-research`
- `$spec-contract-compliance-review`
- `$architecture-design-review`
- `$multi-agent-pr-review`
- `$performance-ab-benchmark-review`
- `$release-readiness-review`

BACnet compliance reviewer panel:

- `bacnet-reference-researcher`
- `bacnet-ip-bvll-reviewer`
- `bacnet-sc-security-reviewer`
- `bacnet-tsm-network-reviewer`
- `bacnet-services-objects-reviewer`
- `bacnet-data-link-reviewer`
- `bacnet-performance-reviewer`
- `bacnet-safety-interop-reviewer`
- `bacnet-pr-packager`
