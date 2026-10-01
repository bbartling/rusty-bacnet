#!/usr/bin/env python3
"""Check that every `file::test` evidence anchor in the conformance ledger resolves.

An anchor is `path/to/file.rs` (file must exist) or `path/to/file.rs::[mod::]name`
where `name` must be a test function defined in that file: `fn name(` carrying a
test attribute (`#[test]`, `#[tokio::test]`, `#[rstest]`, ...), or, for tests a
macro generates, `name` as the leading argument of a macro invocation in that
file. Every `mod` segment must be declared in the file. Python anchors
are `file.py::Class::test`, `file.py::Class.test`, `file.py::Class` or `file.py::test`.

Entry syntax: an optional trailing ` (free-text note)` is ignored, `a; b` lists
several anchors, and `{x,y}` expands in the file path or the test list. A path
with no `::` may be a directory or file and only has to exist.
"""

from __future__ import annotations

import json
import re
import sys
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs" / "conformance" / "bacnet-135-2020.json"
FIELDS = ("positive_tests", "negative_tests")
TEST_ATTR = re.compile(r"#\[\s*(?:[\w:]+::)?(?:test|rstest|test_case|wasm_bindgen_test)\b")


@lru_cache(maxsize=None)
def _source(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _defines_test_fn(src: str, name: str) -> bool:
    for m in re.finditer(rf"\bfn\s+{re.escape(name)}\s*[(<]", src):
        # Walk back over the attribute/comment lines directly above the fn.
        lines = src[: m.start()].split("\n")[:-1]  # drop the fn's own partial line
        # The fn may share its line with leading qualifiers (async, pub).
        for line in reversed(lines):
            s = line.strip()
            if s.startswith("#[") or s.startswith("///") or s.startswith("//") or s == "" or s.startswith("#!["):
                if TEST_ATTR.search(s):
                    return True
                if s == "":
                    break
                continue
            break
    return False


def _macro_generates(src: str, name: str) -> bool:
    """`name` is the leading bare identifier of a macro call (`m!(name, ..)`,
    `m! { name: .. }`), as in macro-generated tests."""
    n = re.escape(name)
    return re.search(rf"\b\w+!\s*[(\[{{]\s*{n}\s*[,:)]", src) is not None


def _expand(anchor: str) -> list[str]:
    """Split `a; b` entries and expand `{x,y}` groups, in file paths or test lists."""
    out: list[str] = []
    for part in anchor.split("; "):
        m = re.search(r"\{([^{}]*)\}", part)
        if not m:
            out.append(part.strip())
            continue
        for alt in m.group(1).split(","):
            out += _expand(part[: m.start()] + alt.strip() + part[m.end() :])
    return out


def _strip_note(anchor: str) -> str:
    """Drop a trailing ` (free-text note)` annotation."""
    return anchor.split(" (", 1)[0].strip()


def _resolve_python(src: str, rest: str) -> str | None:
    *classes, name = re.split(r"::|\.", rest)
    for cls in classes:
        if not re.search(rf"^\s*class\s+{re.escape(cls)}\b", src, re.M):
            return f"class `{cls}` not defined in file"
    if re.search(rf"^\s*(?:async\s+)?def\s+{re.escape(name)}\s*\(", src, re.M):
        return None
    if not classes and re.search(rf"^\s*class\s+{re.escape(name)}\b", src, re.M):
        return None  # a whole test class
    return f"no test `{name}` in file"


def resolve(anchor: str, root: Path = ROOT) -> str | None:
    """Return None if the anchor resolves, else a reason string."""
    anchors = _expand(_strip_note(anchor))
    if len(anchors) > 1 or anchors[0] != anchor:
        reasons = [r for a in anchors if (r := resolve(a, root))]
        return "; ".join(reasons) or None
    path_s, _, rest = anchor.partition("::")
    path = root / path_s
    if not path.exists():
        return "file does not exist"
    if not rest:
        return None
    src = _source(path)
    if src is None:
        return "file unreadable"
    if path.suffix == ".py":
        return _resolve_python(src, rest)
    *mods, name = rest.split("::")
    for mod in mods:
        if not re.search(rf"\bmod\s+{re.escape(mod)}\b", src):
            return f"module `{mod}` not declared in file"
    if _defines_test_fn(src, name) or _macro_generates(src, name):
        return None
    if not mods and re.search(rf"\bmod\s+{re.escape(name)}\b", src):
        return None  # a whole test module
    return f"no test function `{name}` in file"


def stale_anchors(data: dict, root: Path = ROOT) -> list[tuple[str, str, str]]:
    out = []
    for row in data["rows"]:
        for field in FIELDS:
            for anchor in row.get(field, []):
                why = resolve(anchor, root)
                if why:
                    out.append((row["id"], anchor, why))
    return out


def self_test() -> list[str]:
    """The resolver must flag a fixture anchor that cannot resolve."""
    bad = [
        "scripts/check_ledger_anchors.py::no_such_test_anywhere",
        "scripts/no_such_file.rs::x",
        "crates/bacnet-server/src/server/confirmed_tracker_tests.rs::no_such_test_anywhere",
    ]
    return [a for a in bad if resolve(a) is None]


def check(data: dict) -> int:
    """Run the self-test and the ledger check; print findings, return an exit code."""
    failures = self_test()
    for a in failures:
        print(f"self-test: unresolvable fixture anchor was accepted: {a}")
    stale = stale_anchors(data)
    for row_id, anchor, why in stale:
        print(f"stale anchor in {row_id}: {anchor} ({why})")
    if stale:
        print(f"{len(stale)} stale ledger test anchor(s)")
    return 1 if (stale or failures) else 0


def main() -> int:
    return check(json.loads(LEDGER.read_text(encoding="utf-8")))


if __name__ == "__main__":
    sys.exit(main())
