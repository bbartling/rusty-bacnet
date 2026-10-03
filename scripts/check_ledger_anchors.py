#!/usr/bin/env python3
"""Check that every evidence anchor and public claim in the conformance ledger resolves.

An anchor is `path/to/file.rs` (file must exist) or `path/to/file.rs::[mod::]name`
where `name` must be a test function defined in that file: `fn name(` carrying a
test attribute (`#[test]`, `#[tokio::test]`, `#[rstest]`, ...), or, for tests a
macro generates, `name` as the leading argument of a macro invocation in that
file. Every `mod` segment must be declared in the file. Python anchors
are `file.py::Class::test`, `file.py::Class.test`, `file.py::Class` or `file.py::test`.

Entry syntax: an optional trailing ` (free-text note)` is ignored, `a; b` lists
several anchors, and `{x,y}` expands in the file path or the test list. A path
with no `::` may be a directory or file and only has to exist.

A `code_anchors` or `benchmarks` entry is a path or a glob (`*`, `?`, `[...]`)
that must match at least one existing file or directory, optionally followed by
`::`-separated names (`file.rs::Type::method`) that must each appear as a whole
word in a matched file. The same note, `; ` and `{x,y}` syntax applies.

A `public_claims` entry is `path[#heading-slug] [free-text note]`. The file must
exist and a `#slug` must match a heading in it (GitHub slug rules, so a heading
rename or removal is caught). A Markdown claim must name its section: a bare
`.md` path is rejected because a reader cannot check it. Two kinds of path may
stay bare and are only checked for existence: source files (`.rs`, `.pyi`),
which have no headings, and `CHANGELOG.md`, whose headings (`### Fixed`,
`### Added`) repeat under every release and move at release time, so a slug
would be positional and wrong after the next cut. A CHANGELOG claim names the
entry in its free-text note instead.
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
PATH_FIELDS = ("code_anchors", "benchmarks")
FENCE = "`" * 3
BARE_OK = {"CHANGELOG.md"}
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


def resolve_path(anchor: str, root: Path = ROOT) -> str | None:
    """Return None if a `code_anchors` or `benchmarks` entry resolves, else a reason string."""
    anchors = _expand(_strip_note(anchor))
    if len(anchors) > 1 or anchors[0] != anchor:
        reasons = [r for a in anchors if (r := resolve_path(a, root))]
        return "; ".join(reasons) or None
    path_s, _, rest = anchor.partition("::")
    if not path_s:
        return "empty path"
    if re.search(r"[*?\[]", path_s):
        paths = sorted(root.glob(path_s))
        if not paths:
            return "glob matches no file"
    else:
        paths = [root / path_s]
        if not paths[0].exists():
            return "file does not exist"
    for name in rest.split("::") if rest else []:
        word = re.compile(rf"\b{re.escape(name)}\b")
        if not any(word.search(_source(p) or "") for p in paths if p.is_file()):
            return f"`{name}` does not appear in the file"
    return None


def stale_paths(data: dict, root: Path = ROOT) -> list[tuple[str, str, str]]:
    out = []
    for row in data["rows"]:
        for field in PATH_FIELDS:
            for anchor in row.get(field, []):
                why = resolve_path(anchor, root)
                if why:
                    out.append((row["id"], anchor, why))
    return out


def heading_slugs(src: str) -> set[str]:
    """GitHub-style anchors of the Markdown headings in `src` (fenced code skipped)."""
    slugs: set[str] = set()
    seen: dict[str, int] = {}
    fenced = False
    for line in src.split("\n"):
        if line.lstrip().startswith((FENCE, "~~~")):
            fenced = not fenced
            continue
        m = None if fenced else re.match(r"#{1,6}\s+(.*?)\s*#*\s*$", line)
        if not m:
            continue
        text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", m.group(1)).replace("`", "").lower()
        slug = re.sub(r"[^\w\- ]", "", text).replace(" ", "-")
        n = seen.get(slug, 0)
        seen[slug] = n + 1
        slugs.add(slug if n == 0 else f"{slug}-{n}")
    return slugs


def resolve_claim(claim: str, root: Path = ROOT) -> str | None:
    """Return None if a `public_claims` entry resolves, else a reason string."""
    target = claim.split(None, 1)[0] if claim.strip() else ""
    path_s, _, slug = target.partition("#")
    if not path_s:
        return "empty claim"
    path = root / path_s
    if not path.is_file():
        return f"file `{path_s}` does not exist"
    if not slug:
        if path.suffix == ".md" and path.name not in BARE_OK:
            return f"`{path_s}` claim names no section (use `{path_s}#heading-slug`)"
        return None
    src = _source(path)
    if src is None:
        return "file unreadable"
    if slug not in heading_slugs(src):
        return f"no heading `#{slug}` in `{path_s}`"
    return None


def stale_claims(data: dict, root: Path = ROOT) -> list[tuple[str, str, str]]:
    out = []
    for row in data["rows"]:
        for claim in row.get("public_claims", []):
            why = resolve_claim(claim, root)
            if why:
                out.append((row["id"], claim, why))
    return out


def self_test() -> list[str]:
    """The resolver must flag a fixture anchor that cannot resolve."""
    bad = [
        "scripts/check_ledger_anchors.py::no_such_test_anywhere",
        "scripts/no_such_file.rs::x",
        "crates/bacnet-server/src/server/confirmed_tracker_tests.rs::no_such_test_anywhere",
    ]
    bad_claims = [
        "README.md",
        "README.md supported services",
        "docs/rust-api.md",
        "docs/python-api.md some note",
        "docs/conformance/standard-135-2020-ledger.md",
        "README.md#no-such-heading-anywhere",
        "docs/no_such_file.md#x",
        "docs/rust-api.md#no-such-heading-anywhere",
    ]
    bad_paths = [
        "scripts/no_such_file.rs",
        "crates/no-such-crate-*/src",
        "scripts/ledger_schema.py::no_such_symbol_anywhere",
        "crates/bacnet-*/src/no_such_module_anywhere.rs",
    ]
    return (
        [a for a in bad if resolve(a) is None]
        + [c for c in bad_claims if resolve_claim(c) is None]
        + [p for p in bad_paths if resolve_path(p) is None]
    )


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
    claims = stale_claims(data)
    for row_id, claim, why in claims:
        print(f"stale public claim in {row_id}: {claim} ({why})")
    if claims:
        print(f"{len(claims)} stale ledger public claim(s)")
    paths = stale_paths(data)
    for row_id, anchor, why in paths:
        print(f"stale code or benchmark anchor in {row_id}: {anchor} ({why})")
    if paths:
        print(f"{len(paths)} stale ledger code or benchmark anchor(s)")
    return 1 if (stale or claims or paths or failures) else 0


def main() -> int:
    return check(json.loads(LEDGER.read_text(encoding="utf-8")))


if __name__ == "__main__":
    sys.exit(main())
