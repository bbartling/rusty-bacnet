#!/usr/bin/env python3
"""Store conformance ledger notes as one entry per topic (#1176).

A row's `notes` in docs/conformance/bacnet-135-2020.json is either one string
or an array of strings. An array reads as one text when its entries are joined
with single spaces (`notes_text`), which is what the generated docs print. The
array form keeps one topic per JSON line, so two PRs that edit different
entries of the same row merge without a textual conflict.

Run with no arguments to rewrite every string `notes` in the ledger as an
array. Each entry starts at an issue marker (`#NNNN:`, `Refs #NNNN and #MMMM:`)
or else at a sentence boundary, and sentences are grouped so that no entry is
shorter than MIN_CHUNK characters unless a marker forces the split. A note
shorter than MIN_CHUNK stays one entry. The split never changes text: it only
breaks at single spaces, so joining the entries with single spaces gives back
the original string, and each entry keeps the original source bytes (escapes
included). Only the `notes` lines change. Rows that already hold an array are
left alone, so the script is safe to re-run.

`--check` exits 1, without writing, if any row still holds a string.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs" / "conformance" / "bacnet-135-2020.json"

# Group sentences until an entry reaches this many characters.
MIN_CHUNK = 200

# Words that end with a period without ending the sentence.
ABBREVIATIONS = frozenset(
    "approx ca cf e.g eq fig i.e incl no p pp resp sec viz vol vs".split()
)

# An issue marker opening a paragraph: `#1055:`, `Refs #876:`,
# `Refs #875 and #879:`, `Refs #1025, following #999:`.
MARKER = re.compile(r"(?:Refs (?:GitLab )?)?#\d+[^.:]{0,40}:")

# One `"notes": "..."` line of the ledger, with the literal kept verbatim.
NOTES_LINE = re.compile(r'^(?P<indent>[ \t]*)"notes":[ \t]*(?P<lit>"(?:[^"\\]|\\.)*")(?P<comma>,?)[ \t]*$')


def notes_text(notes: str | list[str]) -> str:
    """A row's notes as one string: an array's entries joined with single spaces."""
    if isinstance(notes, str):
        return notes
    if isinstance(notes, list) and all(isinstance(entry, str) for entry in notes):
        return " ".join(notes)
    raise TypeError(f"notes must be a string or an array of strings, not {notes!r}")


def _sentence_break(text: str, i: int) -> bool:
    """Whether the space at `text[i]` ends a sentence."""
    if i < 1 or i + 1 >= len(text) or text[i + 1] == " ":
        return False
    end = i - 1
    if text[end] in ")\"'" and end > 0:
        end -= 1  # `(see Clause 5.) Next` or a closing quote
    if text[end] != "." or (end > 0 and text[end - 1] == "."):
        return False  # no period, or an ellipsis
    word = text[:end].rsplit(" ", 1)[-1].lstrip("([\"'").lower()
    if word in ABBREVIATIONS:
        return False
    nxt = text[i + 1 :].split(" ", 1)[0]
    # Prose sentences start in upper case, digits or `#`; a lower-case start
    # only counts when the word is code (`decode_npdu`, `cov-increment`, `macOS`).
    return not nxt[0].islower() or re.search(r"[_:(!\-A-Z]", nxt) is not None


def sentences(text: str) -> list[str]:
    """`text` cut at the single spaces that end a sentence."""
    out: list[str] = []
    start = 0
    for i, ch in enumerate(text):
        if ch == " " and _sentence_break(text, i):
            out.append(text[start:i])
            start = i + 1
    return out + [text[start:]]


def split_notes(text: str) -> list[str]:
    """Split one notes string into topic entries; `" ".join` of the result is `text`."""
    if len(text) < MIN_CHUNK:
        return [text] if text else []
    # Sentences grouped into paragraphs, each paragraph opened by an issue marker.
    paragraphs: list[list[str]] = []
    for sentence in sentences(text):
        if not paragraphs or MARKER.match(sentence):
            paragraphs.append([])
        paragraphs[-1].append(sentence)
    entries = [entry for paragraph in paragraphs for entry in _group(paragraph)]
    assert " ".join(entries) == text
    return entries


def _group(sentences: list[str]) -> list[str]:
    """Join consecutive sentences until each entry reaches MIN_CHUNK; a short
    remainder joins the paragraph's previous entry."""
    entries: list[str] = []
    current: list[str] = []
    for sentence in sentences:
        current.append(sentence)
        if len(" ".join(current)) >= MIN_CHUNK:
            entries.append(" ".join(current))
            current = []
    if current:
        if entries:
            entries[-1] += " " + " ".join(current)
        else:
            entries.append(" ".join(current))
    return entries


def convert(source: str) -> tuple[str, int]:
    """Rewrite every string `notes` line in ledger source text as an array,
    one entry per line. Returns the new text and the number of rows converted."""
    out: list[str] = []
    converted = 0
    for line in source.split("\n"):
        m = NOTES_LINE.match(line)
        if not m:
            out.append(line)
            continue
        indent, lit, comma = m.group("indent"), m.group("lit"), m.group("comma")
        # Split the literal as written, so each entry keeps its source bytes.
        entries = split_notes(lit[1:-1])
        if entries:
            body = [f'{indent} "{entry}",' for entry in entries]
            body[-1] = body[-1][:-1]
            out += [f'{indent}"notes": [', *body, f"{indent}]{comma}"]
        else:
            out.append(f'{indent}"notes": []{comma}')
        converted += 1
    text = "\n".join(out)
    _verify(source, text)
    return text, converted


def _joined(data: dict) -> dict:
    rows = [dict(row, notes=notes_text(row["notes"])) if "notes" in row else row for row in data["rows"]]
    return dict(data, rows=rows)


def _verify(before: str, after: str) -> None:
    """The rewrite changes only the form of row notes, never their text."""
    old, new = json.loads(before), json.loads(after)
    if _joined(old) != _joined(new):
        raise ValueError("notes conversion changed the ledger's content")
    strings = unconverted(new)
    if strings:
        raise ValueError(f"notes left as strings in {', '.join(strings)}")


def unconverted(data: dict) -> list[str]:
    """IDs of rows whose notes are still one string."""
    return [row["id"] for row in data["rows"] if isinstance(row.get("notes"), str)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("ledger", nargs="?", type=Path, default=LEDGER)
    parser.add_argument("--check", action="store_true", help="fail if any row's notes are still a string")
    args = parser.parse_args(argv)
    source = args.ledger.read_text(encoding="utf-8")
    if args.check:
        left = unconverted(json.loads(source))
        for row_id in left:
            print(f"string notes: {row_id}")
        return 1 if left else 0
    text, converted = convert(source)
    if text != source:
        args.ledger.write_text(text, encoding="utf-8")
    print(f"converted notes in {converted} row(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
