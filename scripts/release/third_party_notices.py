#!/usr/bin/env python3
"""Write THIRD-PARTY-NOTICES for the release binaries (#943).

    third_party_notices.py --out THIRD-PARTY-NOTICES [--libpcap /opt/libpcap]

Lists what the release binaries link statically, with every licence file each
component ships:
- the Rust crates in the bacnet CLI (features sc-tls and pcap) and in the
  rusty_bacnet Python extension, on both Linux targets: `cargo tree` with
  normal edges only, so build scripts, proc-macros and dev-dependencies, which
  end up in neither binary, are left out;
- libpcap, which the CLI links statically (--libpcap: a directory with its
  LICENSE and VERSION, which the CI image installs under /opt/libpcap).

Identical licence texts are printed once, followed by every crate that ships
them. The output depends only on Cargo.lock, the crate sources and libpcap, so
a rebuild produces the same file. Run `cargo fetch --locked` first: cargo runs
with --offline here.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ARTIFACTS = {
    "CLI": ["-p", "bacnet-cli", "--features", "sc-tls,pcap"],
    "Python": ["-p", "rusty-bacnet"],
}
TARGETS = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]
LICENSE_FILE = re.compile(r"^(licen[cs]e|copying|copyright|notice|unlicense)([-._].*)?$", re.IGNORECASE)
SOURCE_SUFFIXES = {".rs", ".py", ".toml", ".json", ".sh", ".c", ".h", ".yml", ".yaml", ".html"}
# Licence files below a crate's root that cover code compiled into it.
EXTRA_FILES = {"aws-lc-sys": ["aws-lc/LICENSE"]}  # the bundled AWS-LC C library
TREE_LINE = re.compile(r"^(\S+) v(\S+)")
RULE = "=" * 79


class NoticesError(Exception):
    """The notices can't be generated faithfully."""


def cargo(*args):
    return subprocess.run(["cargo", *args], check=True, capture_output=True, text=True).stdout


def parse_tree(text):
    """{(name, version)} from `cargo tree --prefix none --format {p}` output."""
    return {m.groups() for m in map(TREE_LINE.match, text.splitlines()) if m}


def linked_crates():
    """{(name, version): {artifact labels}} for every crate linked into a release binary."""
    used = {}
    for label, args in ARTIFACTS.items():
        for target in TARGETS:
            out = cargo("tree", "--locked", "--offline", *args, "--target", target,
                        "-e", "normal,no-proc-macro", "--prefix", "none", "--format", "{p}")
            for crate in parse_tree(out):
                used.setdefault(crate, set()).add(label)
    return used


def index_packages(metadata):
    """{(name, version): package} from `cargo metadata`; refuses ambiguous pairs."""
    index = {}
    for pkg in metadata["packages"]:
        key = (pkg["name"], pkg["version"])
        if key in index:
            raise NoticesError(f"{key[0]} {key[1]} comes from two sources")
        index[key] = pkg
    return index


def normalize(text):
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]
    return "\n".join(lines).strip("\n") + "\n"


def license_files(pkg):
    """[(file name as shown, text)] for the licence files a package ships."""
    root = Path(pkg["manifest_path"]).parent
    paths = sorted(p for p in root.iterdir()
                   if p.is_file() and LICENSE_FILE.match(p.name) and p.suffix.lower() not in SOURCE_SUFFIXES)
    if pkg.get("license_file"):
        declared = Path(os.path.normpath(root / pkg["license_file"]))
        if declared.is_file() and not any(declared.samefile(p) for p in paths):
            paths.append(declared)
    for extra in EXTRA_FILES.get(pkg["name"], []):
        path = root / extra
        if not path.is_file():
            raise NoticesError(f"{pkg['name']} {pkg['version']} no longer has {extra}; update EXTRA_FILES")
        paths.append(path)
    return [(str(p.relative_to(root)) if p.is_relative_to(root) else p.name,
             normalize(p.read_text(encoding="utf-8", errors="replace"))) for p in paths]


def render(version, own_license, crates, libpcap):
    """The notices text.

    crates: [(name, version, licence expression, repository, {labels}, [(file, text)])];
    libpcap: (version, licence text) or None.
    """
    labels = {"CLI": "CLI", "Python": "Python"}
    out = [
        "THIRD-PARTY NOTICES", RULE, "",
        f"Rusty BACnet {version} release binaries:",
        "- CLI: the bacnet command-line tool (bacnet-linux-amd64, bacnet-linux-arm64),",
        "  built with the sc-tls and pcap features;",
        "- Python: the rusty_bacnet extension module in the wheels.",
        "",
        "Rusty BACnet itself is under the MIT licence, below. The binaries also",
        "contain the third-party software listed after it, which is under the",
        "licences that follow the list.",
        "", RULE, "Rusty BACnet", RULE, "", own_license.rstrip("\n"), "",
        RULE, "Components (licence as declared, and the binaries that contain it)", RULE, "",
    ]
    rows = [(n, v, lic or "(none declared)", " ".join(labels[x] for x in sorted(used)))
            for n, v, lic, _repo, used, _files in crates]
    if libpcap:
        rows.append(("libpcap", libpcap[0], "BSD-3-Clause", "CLI"))
    for name, ver, lic, used in sorted(rows):
        out.append(f"{name} {ver}: {lic} [{used}]")
    if libpcap:
        out += ["", RULE, f"libpcap {libpcap[0]} (https://www.tcpdump.org/), linked into the CLI", RULE, "",
                libpcap[1].rstrip("\n")]

    groups = {}
    missing = []
    for name, ver, lic, repo, _used, files in crates:
        if not files:
            missing.append(f"{name} {ver}: {lic or '(none declared)'}{f', {repo}' if repo else ''}")
        for file_name, text in files:
            groups.setdefault(text, []).append(f"{name} {ver} ({file_name})")
    out += ["", RULE, "Licence texts, each followed by the crates that ship it", RULE]
    for text, users in sorted(groups.items(), key=lambda item: sorted(item[1])[0]):
        out += ["", "-" * 79, *[f"  {u}" for u in sorted(users)], "-" * 79, "", text.rstrip("\n")]
    if missing:
        out += ["", RULE, "Crates whose package has no licence file (licence as declared)", RULE, "", *missing]
    return "\n".join(out) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--license", default="LICENSE", type=Path, help="Rusty BACnet's own licence")
    parser.add_argument("--libpcap", type=Path, help="directory with libpcap's LICENSE and VERSION")
    args = parser.parse_args(argv)
    try:
        metadata = json.loads(cargo("metadata", "--format-version", "1", "--locked", "--offline", "--all-features"))
        index = index_packages(metadata)
        members = set(metadata["workspace_members"])
        version = next(p["version"] for p in metadata["packages"] if p["name"] == "rusty-bacnet")
        crates = []
        for key, used in sorted(linked_crates().items()):
            pkg = index.get(key)
            if pkg is None:
                raise NoticesError(f"cargo tree lists {key[0]} {key[1]}, which cargo metadata doesn't")
            if pkg["id"] in members:
                continue
            crates.append((pkg["name"], pkg["version"], pkg.get("license"), pkg.get("repository"), used,
                           license_files(pkg)))
        libpcap = None
        if args.libpcap:
            libpcap = ((args.libpcap / "VERSION").read_text().strip(),
                       normalize((args.libpcap / "LICENSE").read_text(encoding="utf-8")))
        text = render(version, normalize(args.license.read_text(encoding="utf-8")), crates, libpcap)
    except (NoticesError, OSError, subprocess.CalledProcessError) as err:
        detail = getattr(err, "stderr", "") or ""
        print(f"error: {err}\n{detail}".rstrip(), file=sys.stderr)
        return 1
    args.out.write_text(text, encoding="utf-8")
    without = sum(1 for c in crates if not c[5])
    print(f"wrote {args.out}: {len(crates)} crates{', libpcap' if libpcap else ''}, {len(text)} characters;"
          f" {without} crates ship no licence file")
    return 0


if __name__ == "__main__":
    sys.exit(main())
