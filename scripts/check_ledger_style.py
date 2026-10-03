#!/usr/bin/env python3
"""Check conformance ledger rows against the lean schema's caps and style rules (#1209).

Rows listed in scripts/ledger_style_pending.txt (one row ID per line; `#`
starts a comment) are still in the old schema, so only two rules apply to
them: no keys outside the lean and legacy sets, and notes as an array. Every
other row must pass every rule below. Each condense batch of #1208 deletes the
lines of the rows it rewrites. docs/conformance/README.md explains the rules
for writers; each failure prints its rule and a fix.

generate-conformance-docs.py --check runs this check, and CI's Lint job runs
it directly: python3 scripts/check_ledger_style.py
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import ledger_schema

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs" / "conformance" / "bacnet-135-2020.json"
PENDING = ROOT / "scripts" / "ledger_style_pending.txt"

SUMMARY_MAX = 200
NOTES_MAX = 5
NOTE_MAX = 240
GAP_MAX = 200
ANCHOR_MAX = 100

# History narration and normative wording, matched without case outside
# backticked code. History belongs in git; open work belongs in gaps.
BANNED = {
    "Split child": r"\bsplit child",
    "Before,": r"\bbefore,",
    "remains open": r"\bremains open\b",
    "open/partial": r"\bopen/partial\b",
    "tranche": r"\btranche",  # tranches too
    "shall": r"\bshall\b",
    "must": r"\bmust\b",
}
_BANNED = [(phrase, re.compile(pattern, re.I)) for phrase, pattern in BANNED.items()]
ISSUE = re.compile(r"(?<![\w&/])#\d+\b")
GAP_REF = re.compile(r"^#\d+: \S|\((?:no issue|not planned)\)$")
PAGE = re.compile(r"\bpp?\.\s*\d|\bpages?\b|\bprinted|\bpdf\s*(?:pp?\.\s*)?\d", re.I)
CODE_SPAN = re.compile(r"`[^`]*`")

HINTS = {
    "keys": "a lean row holds only " + ", ".join(sorted(ledger_schema.LEAN_KEYS)) + "; fold any other content into summary, notes or gaps",
    "summary": f"write `summary` as one plain sentence of at most {SUMMARY_MAX} characters on what the stack does",
    "notes-shape": "make `notes` an array of non-empty strings without outer whitespace, one topic per entry ([] for none)",
    "notes-cap": f"keep at most {NOTES_MAX} notes of {NOTE_MAX} characters each: local choices and readings only, no history",
    "gaps-shape": "make `gaps` an array of non-empty strings without outer whitespace",
    "gaps-required": "a status other than supported-with-clause-evidence or unsupported-by-design needs at least one gap naming the open work",
    "gap-cap": f"keep each gap within {GAP_MAX} characters; split two topics into two gaps",
    "gap-ref": "start the gap with `#N: ` for its issue, or end it with `(no issue)` or `(not planned)`",
    "issue-outside-gaps": "move the issue number into a gap entry; summary, notes and standard_anchor carry no issue or PR numbers",
    "anchor-cap": f"cite clause, table and annex numbers only, in at most {ANCHOR_MAX} characters",
    "anchor-page": "drop the page reference and cite the clause, table or annex number",
    "banned-phrase": "say what the stack does: no history, no restated normative wording (cite the clause instead); open work goes in gaps",
    "pending": "delete the line from scripts/ledger_style_pending.txt",
}


@dataclass(frozen=True)
class Problem:
    """One rule failure for one row (or one pending-list line)."""

    row: str
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.row}: [{self.rule}] {self.detail}\n    fix: {HINTS[self.rule]}"


def load_pending(path: Path = PENDING) -> list[str]:
    """Row IDs the checker skips, in file order."""
    if not path.exists():
        return []
    lines = (line.split("#", 1)[0].strip() for line in path.read_text(encoding="utf-8").splitlines())
    return [line for line in lines if line]


def _string_list(row: dict, key: str, rule: str, out: list[Problem]) -> list[str] | None:
    """`row[key]` when it is an array of trimmed non-empty strings, else None (and a problem)."""
    value = row[key]
    if not isinstance(value, list):
        out.append(Problem(row["id"], rule, f"`{key}` is {type(value).__name__}, not an array"))
        return None
    bad = [entry for entry in value if not isinstance(entry, str) or not entry or entry.strip() != entry]
    for entry in bad:
        out.append(Problem(row["id"], rule, f"`{key}` entry {entry!r} is not a trimmed non-empty string"))
    return None if bad else value


def _clip(text: str) -> str:
    return text if len(text) <= 60 else text[:57] + "..."


def row_problems(row: dict, pending: bool = False) -> list[Problem]:
    """Every rule failure of one row. A pending row is checked for keys and notes shape only."""
    rid = row.get("id", "<no id>")
    out: list[Problem] = []
    allowed = ledger_schema.LEAN_KEYS | (ledger_schema.LEGACY_KEYS if pending else frozenset())
    for key in row:
        if key not in allowed:
            legacy = " (allowed only while the row is pending)" if key in ledger_schema.LEGACY_KEYS else ""
            extra = "; rename it to `summary`" if key == "requirement_summary" else ""
            out.append(Problem(rid, "keys", f"unknown key `{key}`{legacy}{extra}"))
    if "notes" not in row:
        out.append(Problem(rid, "notes-shape", "`notes` is missing"))
        notes = None
    else:
        notes = _string_list(row, "notes", "notes-shape", out)
    if pending:
        return out

    summary = row.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        out.append(Problem(rid, "summary", "`summary` is missing or empty"))
        summary = ""
    elif len(summary) > SUMMARY_MAX:
        out.append(Problem(rid, "summary", f"`summary` has {len(summary)} characters (cap {SUMMARY_MAX})"))
    if notes is not None:
        if len(notes) > NOTES_MAX:
            out.append(Problem(rid, "notes-cap", f"{len(notes)} notes (cap {NOTES_MAX})"))
        for i, note in enumerate(notes):
            if len(note) > NOTE_MAX:
                out.append(Problem(rid, "notes-cap", f"notes[{i}] has {len(note)} characters (cap {NOTE_MAX})"))
    gaps = _string_list(row, "gaps", "gaps-shape", out) if "gaps" in row else []
    if gaps == [] and row.get("status") not in ledger_schema.NO_GAP_STATUSES:
        out.append(Problem(rid, "gaps-required", f"status `{row.get('status')}` but no gaps"))
    gaps = gaps or []
    for i, gap in enumerate(gaps):
        if len(gap) > GAP_MAX:
            out.append(Problem(rid, "gap-cap", f"gaps[{i}] has {len(gap)} characters (cap {GAP_MAX})"))
        if not GAP_REF.search(gap):
            out.append(Problem(rid, "gap-ref", f"gaps[{i}] {_clip(gap)!r} cites no issue"))
    anchor = row.get("standard_anchor", "")
    anchor = anchor if isinstance(anchor, str) else ""
    if len(anchor) > ANCHOR_MAX:
        out.append(Problem(rid, "anchor-cap", f"`standard_anchor` has {len(anchor)} characters (cap {ANCHOR_MAX})"))
    if m := PAGE.search(anchor):
        out.append(Problem(rid, "anchor-page", f"`standard_anchor` cites a page: {m.group(0)!r}"))

    prose = [("summary", summary), ("standard_anchor", anchor)]
    prose += [(f"notes[{i}]", note) for i, note in enumerate(notes or [])]
    for field, text in prose:
        if m := ISSUE.search(text):
            out.append(Problem(rid, "issue-outside-gaps", f"{field} cites {m.group(0)}"))
    prose += [(f"gaps[{i}]", gap) for i, gap in enumerate(gaps)]
    for field, text in prose:
        plain = CODE_SPAN.sub("", text)
        for phrase, pattern in _BANNED:
            if pattern.search(plain):
                out.append(Problem(rid, "banned-phrase", f"{field} uses {phrase!r}"))
    return out


def problems(data: dict, pending: list[str]) -> list[Problem]:
    """Every rule failure in the ledger, plus pending-list lines that name no row."""
    ids = {row.get("id") for row in data["rows"]}
    skip = set(pending)
    out: list[Problem] = []
    seen: set[str] = set()
    for rid in pending:
        if rid in seen:
            out.append(Problem(rid, "pending", "listed twice in the pending list"))
        elif rid not in ids:
            out.append(Problem(rid, "pending", "listed in the pending list but not a ledger row"))
        seen.add(rid)
    for row in data["rows"]:
        out += row_problems(row, pending=row.get("id") in skip)
    return out


def check(data: dict, pending_path: Path = PENDING) -> int:
    """Print every failure; return 1 if there are any."""
    found = problems(data, load_pending(pending_path))
    for problem in found:
        print(problem)
    if found:
        print(f"{len(found)} ledger style problem(s); rules: docs/conformance/README.md")
    return 1 if found else 0


def main() -> int:
    return check(json.loads(LEDGER.read_text(encoding="utf-8")))


if __name__ == "__main__":
    sys.exit(main())
