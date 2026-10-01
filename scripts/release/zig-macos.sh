#!/usr/bin/env bash
# zig for the macOS release builds (#944), set as cargo-zigbuild's zig with
# CARGO_ZIGBUILD_ZIG_PATH. It builds for MACOSX_DEPLOYMENT_TARGET.
#
# cargo-zigbuild compiles and links with `zig cc -target <arch>-macos-none`.
# That target has no OS version, so zig uses its default minimum, macOS 13, and
# it ignores -mmacosx-version-min. This script writes the version into the
# target, as in `x86_64-macos.10.12-none`. Then the binaries' minimum macOS
# (LC_VERSION_MIN_MACOSX or LC_BUILD_VERSION) matches the wheel tags that
# maturin derives from the same variable. Other zig commands and targets pass
# through unchanged. A macOS target without MACOSX_DEPLOYMENT_TARGET is an
# error, so a build can't fall back to zig's default without anyone noticing.
set -euo pipefail

args=()
prev=
for arg in "$@"; do
  if [ "$prev" = -target ]; then
    case $arg in
      *-macos-none)
        version=${MACOSX_DEPLOYMENT_TARGET:-}
        [[ $version =~ ^[0-9]+\.[0-9]+$ ]] || {
          echo "zig-macos.sh: set MACOSX_DEPLOYMENT_TARGET (major.minor) to build $arg, not '$version'" >&2
          exit 2
        }
        arg="${arg%-macos-none}-macos.$version-none"
        ;;
    esac
  fi
  args+=("$arg")
  prev=$arg
done
exec "${ZIG:-zig}" "${args[@]}"
