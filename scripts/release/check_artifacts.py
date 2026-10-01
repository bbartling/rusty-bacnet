#!/usr/bin/env python3
"""Check the Linux release artifacts before anything is published (#943).

    check_artifacts.py DIR --release-version 0.12.0 --glibc 2.17 --python 3.11 3.12 3.13 3.14 \
        --wheel-arch x86_64 aarch64 --cli bacnet-linux-amd64=x86_64 bacnet-linux-arm64=aarch64 \
        --notices THIRD-PARTY-NOTICES

DIR holds the wheels, the sdist and the CLI binaries. The script fails unless:
- there is exactly one sdist, and one manylinux2014 wheel for each Python and
  architecture, all with the release version in PEP 440 form (Cargo's
  0.12.0-rc.1 is Python's 0.12.0rc1);
- with --notices, each wheel has that file in its .dist-info/licenses/ and the
  sdist has it too, byte for byte;
- each wheel's extension module is named for its own Python and architecture;
- every ELF file (each wheel's extension module, each CLI binary) is for its
  architecture (`readelf -h`) and needs no glibc symbol version newer than
  --glibc (`objdump -T`);
- no CLI binary loads libpcap at run time (capture links a static libpcap).
"""

import argparse
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

GLIBC = re.compile(r"\bGLIBC_(\d+(?:\.\d+)+)\b")
WHEEL = re.compile(r"^rusty_bacnet-(?P<ver>[^-]+)-(?P<py>[^-]+)-(?P<abi>[^-]+)-(?P<plat>[^-]+)\.whl$")
SDIST = re.compile(r"^rusty_bacnet-(?P<ver>[^-]+)\.tar\.gz$")
# `readelf -h` names every machine; an x86_64 objdump calls aarch64 "elf64-little".
READELF_MACHINE = {"x86_64": "Advanced Micro Devices X86-64", "aarch64": "AArch64"}
SEMVER = re.compile(r"^(\d+\.\d+\.\d+)(?:-([0-9A-Za-z.-]+))?$")
PRE_RELEASE = {"alpha": "a", "a": "a", "beta": "b", "b": "b", "rc": "rc", "c": "rc", "pre": "rc",
               "preview": "rc", "dev": ".dev"}


def pep440(cargo_version):
    """The Python version maturin gives a Cargo version: 1.2.3-rc.1 is 1.2.3rc1."""
    m = SEMVER.match(cargo_version)
    if not m:
        raise ValueError(f"can't map Cargo version {cargo_version!r} to PEP 440")
    release, pre = m.groups()
    if pre is None:
        return release
    kind, _, number = pre.partition(".")
    if kind.lower() not in PRE_RELEASE or not (number or "0").isdigit():
        raise ValueError(f"can't map Cargo pre-release {pre!r} to PEP 440")
    return f"{release}{PRE_RELEASE[kind.lower()]}{int(number or 0)}"


def version_tuple(text):
    return tuple(int(part) for part in text.split("."))


def max_glibc(objdump_text):
    """The highest GLIBC_x.y version named in `objdump -T` output, or None."""
    found = [version_tuple(v) for v in GLIBC.findall(objdump_text)]
    return max(found) if found else None


def expected_wheel_tags(pythons, arches):
    """(python tag, abi tag, platform tag) for each manylinux2014 wheel."""
    tags = set()
    for py in pythons:
        cp = "cp" + py.replace(".", "")
        for arch in arches:
            tags.add((cp, cp, f"manylinux_2_17_{arch}.manylinux2014_{arch}"))
    return tags


def check_wheel_set(names, pythons, arches, version):
    """Return (errors, wheels) for the file names in the artifact dir."""
    errors = []
    sdists = [m for m in map(SDIST.match, names) if m]
    if len(sdists) != 1:
        errors.append(f"expected one rusty_bacnet sdist, found {len(sdists)}")
    for m in sdists:
        if m["ver"] != version:
            errors.append(f"{m.string} has version {m['ver']}, the release {version}")
    wheels = {}
    for name in names:
        if not name.endswith(".whl"):
            continue
        m = WHEEL.match(name)
        if not m:
            errors.append(f"unexpected wheel name {name}")
            continue
        if m["ver"] != version:
            errors.append(f"{name} has version {m['ver']}, the release {version}")
        wheels[(m["py"], m["abi"], m["plat"])] = name
    want = expected_wheel_tags(pythons, arches)
    for tag in sorted(want - wheels.keys()):
        errors.append("missing wheel for tag " + "-".join(tag))
    for tag in sorted(wheels.keys() - want):
        errors.append(f"unexpected wheel {wheels[tag]}")
    return errors, {tag: name for tag, name in wheels.items() if tag in want}


def extension_suffix(py_tag, arch):
    """The extension module suffix CPython uses for this wheel tag."""
    return f".cpython-{py_tag[2:]}-{arch}-linux-gnu.so"


def run(tool, path, *flags):
    return subprocess.run([tool, *flags, str(path)], check=True, capture_output=True, text=True).stdout


def elf_machine(readelf_header):
    """The Machine field of `readelf -h` output."""
    m = re.search(r"^\s*Machine:\s*(.+?)\s*$", readelf_header, re.MULTILINE)
    return m.group(1) if m else None


def needed_libraries(readelf_dynamic):
    """The NEEDED entries of `readelf -d` output."""
    return re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", readelf_dynamic)


def check_elf(path, label, glibc_limit, arch):
    errors = []
    machine = elf_machine(run("readelf", path, "-h"))
    if machine != READELF_MACHINE[arch]:
        errors.append(f"{label} is a {machine} ELF, not {arch}")
    needed = max_glibc(run("objdump", path, "-T"))
    shown = ".".join(map(str, needed)) if needed else "none"
    print(f"{label}: needs glibc {shown}")
    if needed is None or needed > glibc_limit:
        errors.append(f"{label} needs glibc {shown}, above {'.'.join(map(str, glibc_limit))}")
    return errors


def check_notices(directory, wheels, version, notices):
    """Errors for wheels or an sdist whose THIRD-PARTY-NOTICES is missing or differs."""
    errors = []
    want = notices.read_bytes()
    member = f"rusty_bacnet-{version}.dist-info/licenses/{notices.name}"
    for name in sorted(wheels.values()):
        with zipfile.ZipFile(directory / name) as whl:
            if member not in whl.namelist():
                errors.append(f"{name} lacks {member}")
            elif whl.read(member) != want:
                errors.append(f"{name}'s {member} differs from {notices}")
    sdist = directory / f"rusty_bacnet-{version}.tar.gz"
    if sdist.is_file():
        with tarfile.open(sdist) as tar:
            found = [m for m in tar.getmembers() if m.isfile() and m.name.endswith("/" + notices.name)]
            if len(found) != 1:
                errors.append(f"{sdist.name} has {len(found)} copies of {notices.name}, expected one")
            elif tar.extractfile(found[0]).read() != want:
                errors.append(f"{sdist.name}'s {found[0].name} differs from {notices}")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dir", type=Path)
    parser.add_argument("--release-version", required=True, help="the workspace version, e.g. 0.12.0")
    parser.add_argument("--notices", type=Path, help="THIRD-PARTY-NOTICES every wheel and the sdist must carry")
    parser.add_argument("--glibc", required=True, help="highest glibc version allowed, e.g. 2.17")
    parser.add_argument("--python", nargs="+", required=True, help="CPython versions, e.g. 3.11")
    parser.add_argument("--wheel-arch", nargs="+", required=True, help="wheel architectures")
    parser.add_argument("--cli", nargs="+", default=[], help="NAME=ARCH for each CLI binary")
    args = parser.parse_args(argv)
    for arch in args.wheel_arch + [spec.partition("=")[2] for spec in args.cli]:
        if arch not in READELF_MACHINE:
            parser.error(f"unknown architecture {arch!r}; known: {', '.join(READELF_MACHINE)}")
    limit = version_tuple(args.glibc)
    try:
        version = pep440(args.release_version)
    except ValueError as err:
        parser.error(str(err))

    names = sorted(p.name for p in args.dir.iterdir() if p.is_file())
    errors, wheels = check_wheel_set(names, args.python, args.wheel_arch, version)
    print(f"Python package version: {version}")
    if args.notices:
        errors += check_notices(args.dir, wheels, version, args.notices)
    with tempfile.TemporaryDirectory() as tmp:
        for (py, _abi, plat), name in sorted(wheels.items()):
            arch = next(a for a in args.wheel_arch if plat.endswith("_" + a))
            with zipfile.ZipFile(args.dir / name) as whl:
                modules = [n for n in whl.namelist() if n.endswith(".so")]
                want = extension_suffix(py, arch)
                if len(modules) != 1 or not modules[0].endswith(want):
                    errors.append(f"{name}: extension modules {modules}, expected one ending {want}")
                    continue
                extracted = Path(whl.extract(modules[0], Path(tmp, name)))
            errors += check_elf(extracted, f"{name} ({modules[0]})", limit, arch)
    for spec in args.cli:
        cli_name, _, arch = spec.partition("=")
        path = args.dir / cli_name
        if not path.is_file():
            errors.append(f"missing CLI binary {cli_name}")
            continue
        errors += check_elf(path, cli_name, limit, arch)
        needed_libs = needed_libraries(run("readelf", path, "-d"))
        print(f"{cli_name}: loads {', '.join(needed_libs)}")
        if any("pcap" in lib for lib in needed_libs):
            errors.append(f"{cli_name} loads libpcap dynamically; the release links it statically")

    for err in errors:
        print(f"error: {err}", file=sys.stderr)
    if errors:
        return 1
    notices = f", {args.notices.name} in each" if args.notices else ""
    print(f"OK: {len(wheels)} wheels, one sdist, {len(args.cli)} CLI binaries, glibc <= {args.glibc}{notices}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
