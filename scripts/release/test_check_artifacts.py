#!/usr/bin/env python3
"""Unit tests for check_artifacts.py (no binaries): python3 -m unittest discover -s scripts/release"""

import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import check_artifacts as checks

LINUX = ["manylinux_2_17_x86_64.manylinux2014_x86_64", "manylinux_2_17_aarch64.manylinux2014_aarch64"]
OTHERS = ["macosx_10_12_x86_64", "macosx_11_0_arm64", "win_amd64"]


class WheelSetTests(unittest.TestCase):
    PY = ["3.11", "3.12"]

    def names(self, version="1.2.0", platforms=LINUX):
        out = [f"rusty_bacnet-{version}.tar.gz"]
        for py in ("cp311", "cp312"):
            for plat in platforms:
                out.append(f"rusty_bacnet-{version}-{py}-{py}-{plat}.whl")
        return out

    def test_complete_set(self):
        errors, wheels = checks.check_wheel_set(self.names(), self.PY, LINUX, "1.2.0")
        self.assertEqual((errors, len(wheels)), ([], 4))
        everything = LINUX + OTHERS
        errors, wheels = checks.check_wheel_set(self.names(platforms=everything), self.PY, everything, "1.2.0")
        self.assertEqual((errors, len(wheels)), ([], 10))

    def test_missing_and_unexpected_wheels(self):
        names = self.names()[:-1] + ["rusty_bacnet-1.2.0-cp312-cp312-manylinux_2_39_x86_64.whl"]
        errors, _ = checks.check_wheel_set(names, self.PY, LINUX, "1.2.0")
        self.assertTrue(any("missing wheel for tag cp312-cp312-manylinux_2_17_aarch64" in e for e in errors))
        self.assertTrue(any("unexpected wheel" in e and "2_39" in e for e in errors))

    def test_macos_tag_must_match_exactly(self):
        names = self.names(platforms=["macosx_11_0_arm64"])
        names[-1] = names[-1].replace("macosx_11_0", "macosx_13_0")
        errors, _ = checks.check_wheel_set(names, self.PY, ["macosx_11_0_arm64"], "1.2.0")
        self.assertIn("missing wheel for tag cp312-cp312-macosx_11_0_arm64", errors)
        self.assertTrue(any("unexpected wheel" in e and "macosx_13_0" in e for e in errors))

    def test_version_mismatch_and_missing_sdist(self):
        names = self.names()[1:] + ["rusty_bacnet-1.3.0.tar.gz"]
        names[0] = names[0].replace("1.2.0", "1.1.0")
        errors, _ = checks.check_wheel_set(names, self.PY, LINUX, "1.2.0")
        self.assertTrue(any("has version 1.1.0, the release 1.2.0" in e for e in errors))
        self.assertTrue(any("rusty_bacnet-1.3.0.tar.gz has version 1.3.0, the release 1.2.0" in e for e in errors))
        errors, _ = checks.check_wheel_set(self.names()[1:], self.PY, LINUX, "1.2.0")
        self.assertIn("expected one rusty_bacnet sdist, found 0", errors)

    def test_pre_release_wheels_use_the_pep440_version(self):
        errors, _ = checks.check_wheel_set(self.names("1.2.0rc1"), self.PY, LINUX, checks.pep440("1.2.0-rc.1"))
        self.assertEqual(errors, [])

    def test_pep440(self):
        cases = {"0.12.0": "0.12.0", "1.0.0-rc.1": "1.0.0rc1", "1.0.0-alpha.2": "1.0.0a2", "1.0.0-beta": "1.0.0b0",
                 "2.0.0-dev.3": "2.0.0.dev3"}
        for cargo, python in cases.items():
            with self.subTest(cargo=cargo):
                self.assertEqual(checks.pep440(cargo), python)
        for bad in ("1.0", "1.0.0-nightly.1", "1.0.0-rc.x", "1.0.0+build"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                checks.pep440(bad)

    def test_notices_in_wheels_and_sdist(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            notices = d / "THIRD-PARTY-NOTICES"
            notices.write_bytes(b"notices")
            good, bad, missing = (f"rusty_bacnet-1.2.0-cp31{i}-cp31{i}-x.whl" for i in (1, 2, 3))
            for name, payload in ((good, b"notices"), (bad, b"other")):
                with zipfile.ZipFile(d / name, "w") as whl:
                    whl.writestr("rusty_bacnet-1.2.0.dist-info/licenses/THIRD-PARTY-NOTICES", payload)
            with zipfile.ZipFile(d / missing, "w") as whl:
                whl.writestr("rusty_bacnet/__init__.py", "")
            with tarfile.open(d / "rusty_bacnet-1.2.0.tar.gz", "w:gz") as tar:
                tar.add(notices, "rusty_bacnet-1.2.0/crates/rusty-bacnet/THIRD-PARTY-NOTICES")
            errors = checks.check_notices(d, {1: good, 2: bad, 3: missing}, "1.2.0", notices)
        self.assertEqual(len(errors), 2, errors)
        self.assertTrue(any(bad in e and "differs" in e for e in errors))
        self.assertTrue(any(missing in e and "lacks" in e for e in errors))


class PlatformTests(unittest.TestCase):
    def test_parse_platform(self):
        cases = {
            "manylinux_2_17_x86_64.manylinux2014_x86_64": ("linux", "x86_64", None),
            "manylinux_2_17_aarch64": ("linux", "aarch64", None),
            "linux_aarch64": ("linux", "aarch64", None),
            "macosx_10_12_x86_64": ("macos", "x86_64", (10, 12)),
            "macosx_11_0_arm64": ("macos", "aarch64", (11, 0)),
            "win_amd64": ("windows", "x86_64", None),
        }
        for tag, want in cases.items():
            with self.subTest(tag=tag):
                self.assertEqual(checks.parse_platform(tag), want)
        for bad in ("linux_riscv64", "macosx_11_0_universal2", "win32", "x86_64"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                checks.parse_platform(bad)

    def test_extension_suffix(self):
        self.assertEqual(checks.extension_suffix("cp314", "manylinux_2_17_aarch64.manylinux2014_aarch64"),
                         ".cpython-314-aarch64-linux-gnu.so")
        self.assertEqual(checks.extension_suffix("cp311", "macosx_10_12_x86_64"), ".cpython-311-darwin.so")
        self.assertEqual(checks.extension_suffix("cp312", "win_amd64"), ".cp312-win_amd64.pyd")


class ElfParsingTests(unittest.TestCase):
    def test_max_glibc(self):
        text = (
            "0000 DF *UND* 0000 (GLIBC_2.2.5) memcpy\n"
            "0000 DF *UND* 0000 (GLIBC_2.17) clock_gettime\n"
            "0000 DF *UND* 0000 (GLIBC_2.3) x\n0000 DF *UND* 0000 (GLIBC_PRIVATE) y\n"
        )
        self.assertEqual(checks.max_glibc(text), (2, 17))
        self.assertIsNone(checks.max_glibc("no versions"))
        self.assertGreater(checks.max_glibc("(GLIBC_2.34) z"), (2, 17))

    def test_readelf_parsing(self):
        header = "ELF Header:\n  Class:                             ELF64\n  Machine:                           AArch64\n"
        self.assertEqual(checks.elf_machine(header), "AArch64")
        self.assertIsNone(checks.elf_machine("nothing"))
        dynamic = (
            " 0x0000000000000001 (NEEDED)             Shared library: [libm.so.6]\n"
            " 0x0000000000000001 (NEEDED)             Shared library: [libpcap.so.0.8]\n"
            " 0x000000000000000c (INIT)               0x1000\n"
        )
        self.assertEqual(checks.needed_libraries(dynamic), ["libm.so.6", "libpcap.so.0.8"])


def load_dylib(n, name):
    return (f"Load command {n}\n          cmd LC_LOAD_DYLIB\n      cmdsize 56\n"
            f"         name {name} (offset 24)\n   time stamp 2 Thu Jan  1 00:00:02 1970\n"
            "      current version 1.0.0\ncompatibility version 1.0.0\n")


SIGNATURE = "Load command 30\n      cmd LC_CODE_SIGNATURE\n  cmdsize 16\n  dataoff 123\n datasize 456\n"
FRAMEWORKS = {checks.IOKIT, checks.COREFOUNDATION}


def macho_text(cpu="ARM64", version_cmd=None, dylibs=checks.MACOS_SYSTEM, extra=SIGNATURE):
    version_cmd = version_cmd or ("Load command 1\n       cmd LC_BUILD_VERSION\n   cmdsize 32\n  platform macos\n"
                                  "       sdk 26.4\n     minos 11.0\n    ntools 1\n      tool 0x000005\n"
                                  "   version 0.0\n")
    return ("x.so:\nMach header\n      magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags\n"
            f"MH_MAGIC_64   {cpu}        ALL  0x00       DYLIB    20       2464 DYLDLINK TWOLEVEL\n"
            "Load command 0\n      cmd LC_SEGMENT_64\n  cmdsize 712\n  segname __TEXT\nSection\n  sectname __text\n"
            + version_cmd + "".join(load_dylib(n, d) for n, d in enumerate(sorted(dylibs), 2)) + extra)


BIND_HEAD = ("x.so:\n\nBind table:\n"
             "segment  section            address    type       addend dylib            symbol\n")
LAZY_HEAD = "\nLazy bind table:\nsegment  section            address     dylib            symbol\n"


def got(symbol, dylib="flat-namespace"):
    return f"__DATA_CONST __got              0x01314000 pointer         0 {dylib:<16} {symbol}\n"


def lazy(symbol, dylib="flat-namespace"):
    return f"__DATA   __la_symbol_ptr    0x01334000 {dylib:<16} {symbol}\n"


BIND = (BIND_HEAD + got("_PyExc_BaseException") + got("__Py_NoneStruct") + got("_kCFBooleanTrue")
        + got("_free", "libSystem") + LAZY_HEAD + lazy("_IOServiceMatching") + lazy("_malloc", "libSystem"))
CLI_BIND = BIND_HEAD + got("_free", "libSystem") + LAZY_HEAD + lazy("_malloc", "libSystem")


class MachoTests(unittest.TestCase):
    def test_build_version_dylibs_and_signature(self):
        info = checks.macho_headers(macho_text())
        self.assertEqual((info["cpu"], info["platform"], info["minos"], info["chained"], info["signed"]),
                         ("ARM64", "macos", "11.0", False, True))
        self.assertEqual(info["dylibs"], sorted(checks.MACOS_SYSTEM))
        self.assertFalse(checks.macho_headers(macho_text(extra=""))["signed"])

    def test_version_min_macosx(self):
        cmd = "Load command 1\n      cmd LC_VERSION_MIN_MACOSX\n  cmdsize 16\n  version 10.12\n      sdk 26.4\n"
        info = checks.macho_headers(macho_text("X86_64", cmd))
        self.assertEqual((info["cpu"], info["platform"], info["minos"]), ("X86_64", "macos", "10.12"))

    def test_flat_lookups(self):
        self.assertEqual(checks.flat_lookups(BIND),
                         ["_IOServiceMatching", "_PyExc_BaseException", "__Py_NoneStruct", "_kCFBooleanTrue"])

    def test_symbol_lists(self):
        self.assertEqual((len(checks.IOKIT_SYMBOLS), len(checks.COREFOUNDATION_SYMBOLS)), (10, 72))
        self.assertTrue(all(s.startswith(("_IO", "_kIO")) for s in checks.IOKIT_SYMBOLS))
        self.assertTrue(all(s.startswith(("_CF", "_kCF")) for s in checks.COREFOUNDATION_SYMBOLS))

    def check(self, headers, bind, arch="aarch64", minos=(11, 0), extension=True):
        outputs = {"--private-headers": headers, "--bind": bind}
        with mock.patch.object(checks, "run", lambda _tool, _path, *flags: outputs[flags[1]]), \
                mock.patch("builtins.print"):
            return checks.check_macho(Path("x.so"), "x.so", arch, minos, extension)

    def test_extension_passes(self):
        headers = macho_text(dylibs=checks.MACOS_SYSTEM | FRAMEWORKS)
        self.assertEqual(self.check(headers, BIND), [])

    def test_cli_passes(self):
        self.assertEqual(self.check(macho_text(), CLI_BIND, extension=False), [])

    def test_wrong_arch_minimum_and_extra_dylib(self):
        headers = macho_text(dylibs=checks.MACOS_SYSTEM | FRAMEWORKS | {"/usr/lib/libz.1.dylib"})
        errors = self.check(headers, BIND, arch="x86_64", minos=(10, 12))
        self.assertEqual(len(errors), 3, errors)
        self.assertTrue(any("ARM64 Mach-O, not x86_64" in e for e in errors))
        self.assertTrue(any("needs macOS 11.0, its platform tag says 10.12" in e for e in errors))
        self.assertTrue(any("libz.1.dylib" in e for e in errors))

    def test_arm64_needs_a_code_signature(self):
        unsigned = macho_text(dylibs=checks.MACOS_SYSTEM | FRAMEWORKS, extra="")
        self.assertEqual(self.check(unsigned, BIND),
                         ["x.so has no code signature, which macOS requires on arm64"])
        self.assertEqual(self.check(macho_text(extra=""), CLI_BIND, extension=False),
                         ["x.so has no code signature, which macOS requires on arm64"])
        x86 = macho_text("X86_64", dylibs=checks.MACOS_SYSTEM | FRAMEWORKS, extra="")
        self.assertEqual(self.check(x86, BIND, arch="x86_64"), [])

    def test_extension_needs_the_frameworks_it_looks_up(self):
        errors = self.check(macho_text(), BIND)
        self.assertEqual(errors, [
            f"x.so leaves _IOServiceMatching to a flat lookup but doesn't load {checks.IOKIT}",
            f"x.so leaves _kCFBooleanTrue to a flat lookup but doesn't load {checks.COREFOUNDATION}"])
        only_cf = BIND_HEAD + got("_PyType_Ready") + got("_CFRelease") + got("_free", "libSystem")
        self.assertEqual(self.check(macho_text(dylibs=checks.MACOS_SYSTEM | {checks.COREFOUNDATION}), only_cf), [])

    def test_cli_loads_no_framework_and_leaves_no_flat_lookup(self):
        headers = macho_text(dylibs=checks.MACOS_SYSTEM | FRAMEWORKS)
        errors = self.check(headers, BIND, extension=False)
        self.assertEqual(len(errors), 3, errors)
        self.assertTrue(any("leaves 4 symbols to a flat lookup" in e for e in errors))

    def test_only_the_listed_framework_symbols(self):
        headers = macho_text(dylibs=checks.MACOS_SYSTEM | FRAMEWORKS)
        for symbol in ("_SSLRead", "_CFNetworkCopySystemProxySettings", "_IOSurfaceCreate", "_kCFNull", "_Pz"):
            with self.subTest(symbol=symbol):
                self.assertEqual(self.check(headers, BIND + lazy(symbol)), [
                    "x.so leaves symbols to a flat lookup that neither Python nor the listed framework"
                    f" symbols cover (1): {symbol}"])
        every = BIND_HEAD + got("_Py_IsInitialized") + got("_free", "libSystem") + "".join(
            got(s) for s in sorted(checks.IOKIT_SYMBOLS | checks.COREFOUNDATION_SYMBOLS))
        self.assertEqual(self.check(headers, every), [])

    def test_chained_fixups(self):
        chained = macho_text(dylibs=checks.MACOS_SYSTEM | FRAMEWORKS) + (
            "Load command 9\n      cmd LC_DYLD_CHAINED_FIXUPS\n  cmdsize 16\n")
        self.assertTrue(any("chained fixups" in e for e in self.check(chained, BIND)))

    def test_unparsed_bind_output_fails(self):
        headers = macho_text(dylibs=checks.MACOS_SYSTEM | FRAMEWORKS)
        for bind in ("", "x.so:\n", BIND.replace("Bind table:", "Binds:"), BIND.replace("libSystem", "libc")):
            with self.subTest(bind=bind[:20]):
                errors = self.check(headers, bind)
                self.assertEqual(len(errors), 1, errors)
                self.assertIn("no bind table or libSystem bind", errors[0])
        self.assertIn("no bind table", self.check(macho_text(), "", extension=False)[0])

    def test_extension_without_python_lookups_fails(self):
        no_python = BIND_HEAD + got("_CFRelease") + got("_free", "libSystem")
        self.assertEqual(self.check(macho_text(dylibs=checks.MACOS_SYSTEM | FRAMEWORKS), no_python),
                         ["x.so leaves no Python symbol to a flat lookup; the bind output didn't parse"])


def pe_text(machine="IMAGE_FILE_MACHINE_AMD64", dll=False, subsystem="IMAGE_SUBSYSTEM_WINDOWS_CUI", imports=()):
    flags = "    IMAGE_FILE_DLL (0x2000)\n" if dll else ""
    out = (f"File: x\nFormat: COFF-x86-64\nImageFileHeader {{\n  Machine: {machine} (0x8664)\n"
           f"  Characteristics [ (0x22)\n{flags}    IMAGE_FILE_EXECUTABLE_IMAGE (0x2)\n  ]\n}}\n"
           f"ImageOptionalHeader {{\n  Subsystem: {subsystem} (0x3)\n}}\n")
    for name in imports:
        out += f"Import {{\n  Name: {name}\n  ImportLookupTableRVA: 0x1\n  Symbol: X (0)\n}}\n"
    return out


SYSTEM = ["KERNEL32.dll", "kernel32.dll", "ntdll.dll", "ws2_32.dll", "api-ms-win-core-synch-l1-2-0.dll"]
CRT = ["VCRUNTIME140.dll", "api-ms-win-crt-runtime-l1-1-0.dll"]


class PeTests(unittest.TestCase):
    def check(self, text, python_dll=None, arch="x86_64"):
        with mock.patch.object(checks, "run", return_value=text), mock.patch("builtins.print"):
            return checks.check_pe(Path("x"), "x", arch, python_dll)

    def test_parse(self):
        text = pe_text(dll=True, imports=SYSTEM) + "DelayImport {\n  Name: user32.dll\n}\n"
        info = checks.pe_headers(text)
        self.assertEqual((info["machine"], info["dll"], info["subsystem"]),
                         ("IMAGE_FILE_MACHINE_AMD64", True, "IMAGE_SUBSYSTEM_WINDOWS_CUI"))
        self.assertEqual(info["imports"], SYSTEM + ["user32.dll"])

    def test_static_crt_cli_passes(self):
        self.assertEqual(self.check(pe_text(imports=SYSTEM)), [])

    def test_cli_with_crt_dll_or_python_fails(self):
        errors = self.check(pe_text(imports=SYSTEM + CRT + ["python312.dll"]))
        self.assertEqual(len(errors), 3, errors)
        self.assertEqual(sum("links the CRT statically" in e for e in errors), 2)

    def test_extension(self):
        good = pe_text(dll=True, subsystem="IMAGE_SUBSYSTEM_WINDOWS_GUI", imports=SYSTEM + CRT + ["python312.dll"])
        self.assertEqual(self.check(good, "python312.dll"), [])
        errors = self.check(good, "python313.dll")
        self.assertEqual(errors, ["x imports ['python312.dll'], expected python313.dll"])

    def test_unparsed_imports_fail(self):
        for imports in ((), ["ntdll.dll", "ws2_32.dll"]):
            with self.subTest(imports=imports):
                errors = self.check(pe_text(imports=imports))
                self.assertIn("x doesn't import kernel32.dll; llvm-readobj's import list didn't parse", errors)
        self.assertEqual(checks.pe_headers("")["imports"], [])

    def test_wrong_machine_kind_and_unexpected_dll(self):
        errors = self.check(pe_text(machine="IMAGE_FILE_MACHINE_ARM64", dll=True, imports=SYSTEM + ["libssl-3.dll"]))
        self.assertEqual(len(errors), 3, errors)
        self.assertTrue(any("not a console program" in e for e in errors))
        self.assertTrue(any("libssl-3.dll" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
