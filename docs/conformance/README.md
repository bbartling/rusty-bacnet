# Conformance ledger

[bacnet-135-2020.json](bacnet-135-2020.json) holds one row per area of ANSI/ASHRAE 135-2020 the project tracks. `python3 scripts/generate-conformance-docs.py` writes the [support summary](support-summary.md) and the draft pages from it; `--check` also resolves every anchor and link and runs the style check, `scripts/check_ledger_style.py`.

## Row schema

| Key | Holds |
|---|---|
| `id`, `priority`, `status` | Stable row ID, `P0` to `P3`, and one status from `status_taxonomy`. |
| `standard_anchor` | Clause, table and annex numbers only; at most 100 characters. |
| `summary` | One sentence of at most 200 characters (replaces `requirement_summary`). |
| `notes` | Up to 5 entries of at most 240 characters: local choices and readings. `[]` when there are none. |
| `gaps` | Open work, each entry at most 200 characters, starting with `#N: ` or ending with `(no issue)` or `(not planned)`. Needed unless the status is `supported-with-clause-evidence` or `unsupported-by-design`; a missing key means none. |
| `code_anchors`, `benchmarks` | Paths or globs, optionally followed by `::name`. |
| `positive_tests`, `negative_tests` | Test anchors, `path::test`. |
| `public_claims` | `doc.md#heading` sections that rely on the row. |

No other keys. Rows listed in `scripts/ledger_style_pending.txt` are still in the old schema, so the style check reads only their keys (the old ones, `evidence` included, are allowed there) and their notes. Each condense batch of #1208 removes the rows it rewrites from that list.

## Style rules

1. Describe what the stack does. Cite a clause by number rather than retelling it or copying a table.
2. Write the summary as one sentence for someone deciding whether the feature is usable.
3. Keep notes to local decisions, one topic per entry; add an entry instead of growing one.
4. Put issue numbers in gaps and nowhere else.
5. Leave history to git: no "before", "now", "since", "split from", PR numbers, tranches or "remains open".
6. Give anchors as numbers, without page numbers or descriptions.
7. Use plain words and short sentences, with identifiers in backticks.
8. Paraphrase only, and run `spec_overlap.py` at 8 and 6 words before committing.

## Example

A row in this form, with each list cut to one entry:

```json
{
  "id": "BACNET-15-WP-OUTBOUND-PRIORITY",
  "standard_anchor": "Clause 15.9.1.1",
  "priority": "P1",
  "summary": "Outbound WriteProperty takes no priority or one from 1 to 16 and refuses any other value before encoding or sending.",
  "status": "in-progress",
  "code_anchors": ["crates/bacnet-services/src/write_property.rs::validate_priority"],
  "positive_tests": ["crates/bacnet-services/src/write_property.rs::outbound_priority_none_and_all_valid_values_preserve_bytes"],
  "negative_tests": ["crates/bacnet-client/src/client/write_priority_tests.rs::write_priority_invalid_direct_local_routed_and_batch_never_admit_or_send"],
  "benchmarks": [],
  "public_claims": ["docs/rust-api.md#readproperty--writeproperty"],
  "notes": ["A refused priority leaves the caller's output buffer untouched.", "A Python batch with one bad priority sends no request at all."],
  "gaps": ["Inbound WriteProperty and full service qualification are outside this row (no issue)"]
}
```
