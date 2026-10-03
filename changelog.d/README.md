# Changelog fragments

A change that users can see adds one file here instead of editing
`CHANGELOG.md`, so parallel PRs don't conflict over it. When a version is
released, `scripts/changelog.py assemble` writes the files into a new
`CHANGELOG.md` section and deletes them. This README is not a fragment.

## Writing a fragment

Name the file `<issue>-<short-slug>.md`, for example
`1131-access-door-oos-writes.md`, or `<short-slug>.md` when there is no
issue, using lowercase letters, digits and hyphens. When one issue needs two
entries, give each its own slug (`1092-units.md`, `1092-averaging.md`).

```markdown
---
section: Fixed
---
- **Access Door out-of-service writes (wire):** what changed, from a user's
  point of view, naming the issue (#1131).
  - A nested bullet, indented two spaces.

  A further paragraph, also indented two spaces.
```

- `section` is the heading the entry goes under: `Added`, `Changed`,
  `Deprecated`, `Removed`, `Fixed`, `Security` or `Migration notes`.
- The body is one Markdown bullet starting with `- `, exactly as it will read
  in `CHANGELOG.md`. Indent continuation lines, nested bullets and further
  paragraphs two spaces. Mark wire-format and breaking changes in bold, as the
  existing entries do.
- Write relative links from the repository root (`docs/rust-api.md#bbmd`), as
  `CHANGELOG.md` will see them.
- No trailing whitespace, and the file ends with a single newline.

A release section lists its headings in the order above, and the entries
under each by issue number, then slug; fragments without an issue come last.

Conformance ledger claims keep citing `CHANGELOG.md`, with the issue in the
note, since that is where the entry lands at release.

## Commands

```bash
python3 scripts/changelog.py check     # validate; CI's lint job runs this
python3 scripts/changelog.py preview   # print [Unreleased] as the fragments make it
python3 scripts/changelog.py assemble --version X.Y.Z [--date YYYY-MM-DD]   # at release
```

`check` also fails if `CHANGELOG.md`'s `[Unreleased]` section lists an entry
itself. The release steps are in [docs/ci.md](../docs/ci.md#release).
