# Prebuilt image for the Forgejo CI jobs (#904): the runner's act image plus
# everything the jobs used to install on every run. ci.yml tags it with a hash of
# this file and builds it only when that tag is missing, so any change here, even
# a comment, produces a new tag; release.yml uses the same tag. Never re-push an
# existing tag.
#
# Bumping a pin: the Rust toolchain also lives in rust-toolchain.toml and
# .github/workflows/release.yml; the MSRV in Cargo.toml's rust-version,
# ci.yml's RUSTUP_TOOLCHAIN and scripts/ci/check-msrv.sh. The "CI image" job
# fails if rust-toolchain.toml, Cargo.toml or ci.yml disagree with the ARGs.
# Tool pins sit next to their download, each with the asset's SHA-256.

# The runner's default image, pinned so the tag covers the base as well.
FROM ghcr.io/catthehacker/ubuntu:act-24.04@sha256:62d572b92f9f32d3427b6d220ad1f9dca9c7b6ffad37d295425037dbff78abaf

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

# The union of the jobs' apt packages: pcap for bacnet-cli, cmake/perl for
# aws-lc-rs, python3 with venv and libpython for the PyO3 crate, openssl for the
# SC test certificates, file for the MSRV script.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential pkg-config cmake perl file jq libpcap-dev \
      python3 python3-venv libpython3-dev openssl \
 && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

# fetch <url> <sha256> <file>: download and verify.
RUN printf '%s\n' '#!/bin/bash' 'set -euo pipefail' \
      'curl -sSfL --retry 3 -o "$3" "$1"' \
      'echo "$2  $3" | sha256sum -c --quiet' > /usr/local/bin/fetch \
 && chmod +x /usr/local/bin/fetch

# The CI toolchain with the components the jobs use, and the MSRV toolchain.
ARG RUSTUP_VERSION=1.29.0
ARG RUSTUP_SHA256=4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10
ARG RUST_TOOLCHAIN=1.97.1
ARG RUST_MSRV=1.93
RUN fetch "https://static.rust-lang.org/rustup/archive/$RUSTUP_VERSION/x86_64-unknown-linux-gnu/rustup-init" \
      "$RUSTUP_SHA256" /tmp/rustup-init \
 && chmod +x /tmp/rustup-init \
 && /tmp/rustup-init -y --no-modify-path --profile minimal \
      --default-toolchain "$RUST_TOOLCHAIN" -c rustfmt,clippy \
 && rm /tmp/rustup-init \
 && rustup toolchain install "$RUST_MSRV" --profile minimal \
 && rustc --version && rustup run "$RUST_MSRV" rustc --version

ARG NEXTEST_VERSION=0.9.146
ARG NEXTEST_SHA256=682c21b777c333e96fd532e114d3a5a894e0729ab88d94c0a9f20f8419695428
ARG CARGO_DENY_VERSION=0.20.2
ARG CARGO_DENY_SHA256=9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f
ARG CARGO_AUDIT_VERSION=0.22.2
ARG CARGO_AUDIT_SHA256=7fb9497f8594b389e5fce5ef9b92db08432996895b2e0c5a0167a69ed445c428
ARG MATURIN_VERSION=1.15.0
ARG MATURIN_SHA256=5a7d5226e83598b0c85881a0a03be16393ee2c0924b6f9d752951795825ac806
RUN cd /tmp \
 && bin="$CARGO_HOME/bin" \
 && fetch "https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-$NEXTEST_VERSION/cargo-nextest-$NEXTEST_VERSION-x86_64-unknown-linux-gnu.tar.gz" \
      "$NEXTEST_SHA256" nextest.tgz \
 && tar xzf nextest.tgz -C "$bin" cargo-nextest \
 && deny="cargo-deny-$CARGO_DENY_VERSION-x86_64-unknown-linux-musl" \
 && fetch "https://github.com/EmbarkStudios/cargo-deny/releases/download/$CARGO_DENY_VERSION/$deny.tar.gz" \
      "$CARGO_DENY_SHA256" deny.tgz \
 && tar xzf deny.tgz -C "$bin" --strip-components=1 "$deny/cargo-deny" \
 && audit="cargo-audit-x86_64-unknown-linux-musl-v$CARGO_AUDIT_VERSION" \
 && fetch "https://github.com/rustsec/rustsec/releases/download/cargo-audit%2Fv$CARGO_AUDIT_VERSION/$audit.tgz" \
      "$CARGO_AUDIT_SHA256" audit.tgz \
 && tar xzf audit.tgz -C "$bin" --strip-components=1 "$audit/cargo-audit" \
 && fetch "https://github.com/PyO3/maturin/releases/download/v$MATURIN_VERSION/maturin-x86_64-unknown-linux-musl.tar.gz" \
      "$MATURIN_SHA256" maturin.tgz \
 && tar xzf maturin.tgz -C /usr/local/bin maturin \
 && rm ./*.tgz \
 && cargo nextest --version && cargo deny --version && cargo audit --version && maturin --version

# Release builds (#943, .forgejo/workflows/release.yml): zig links the Linux CLI
# binaries and the manylinux wheels against an old glibc for both architectures,
# through cargo-zigbuild and `maturin build --zig`, and the macOS ones too (see
# below). No extra Pythons: maturin uses its bundled sysconfig for the
# interpreters it can't find.
ARG ZIG_VERSION=0.16.0
ARG ZIG_SHA256=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
ARG CARGO_ZIGBUILD_VERSION=0.23.4
ARG CARGO_ZIGBUILD_SHA256=9e3cf73485edbd45905c8aadbc0fdf869c7ddc3848f0c898229f2680db52e44b
RUN cd /tmp \
 && fetch "https://ziglang.org/download/$ZIG_VERSION/zig-x86_64-linux-$ZIG_VERSION.tar.xz" "$ZIG_SHA256" zig.txz \
 && mkdir /opt/zig \
 && tar xJf zig.txz -C /opt/zig --strip-components=1 \
 && ln -s /opt/zig/zig /usr/local/bin/zig \
 && zigbuild="cargo-zigbuild-x86_64-unknown-linux-musl" \
 && fetch "https://github.com/rust-cross/cargo-zigbuild/releases/download/v$CARGO_ZIGBUILD_VERSION/$zigbuild.tar.xz" \
      "$CARGO_ZIGBUILD_SHA256" zigbuild.txz \
 && tar xJf zigbuild.txz -C "$CARGO_HOME/bin" --strip-components=1 "$zigbuild/cargo-zigbuild" \
 && rm ./*.txz \
 && rustup target add --toolchain "$RUST_TOOLCHAIN" aarch64-unknown-linux-gnu \
 && zig version && cargo zigbuild --help >/dev/null

# A static libpcap for each release target, built for glibc 2.17 like
# release.yml's GLIBC, so the CLI's packet capture needs no libpcap on the
# user's system: Debian and Ubuntu name its shared library libpcap.so.0.8, RHEL
# libpcap.so.1, so one dynamically linked binary can't run on both. release.yml
# points LIBPCAP_LIBDIR at /opt/libpcap/<arch>/lib. The pcap crate links -lpcap
# as a shared library and zig won't fall back to an archive, so a one-line
# linker script named libpcap.so points at libpcap.a. /opt/libpcap/LICENSE and
# VERSION go into the release's THIRD-PARTY-NOTICES. flex and bison only
# generate libpcap's filter parser and are removed again.
ARG LIBPCAP_VERSION=1.10.7
ARG LIBPCAP_SHA256=68fa62cffb974f4275641ce14c2e2d75739251f30e00e6a0900903b247d76a03
RUN dpkg-query -W -f '${Package}\n' | sort >/tmp/packages-before \
 && apt-get update \
 && apt-get install -y --no-install-recommends flex bison \
 && cd /tmp \
 && fetch "https://www.tcpdump.org/release/libpcap-$LIBPCAP_VERSION.tar.xz" "$LIBPCAP_SHA256" libpcap.txz \
 && for arch in x86_64 aarch64; do \
      mkdir "libpcap-$arch" \
      && tar xJf libpcap.txz -C "libpcap-$arch" --strip-components=1 \
      && (cd "libpcap-$arch" \
          && CC="zig cc -target $arch-linux-gnu.2.17" AR="zig ar" RANLIB="zig ranlib" \
             ./configure --quiet --host="$arch-linux-gnu" --disable-shared --with-pcap=linux \
               --without-libnl --disable-dbus --disable-rdma --disable-bluetooth --disable-usb \
               --disable-netmap \
          && make -s -j"$(nproc)" libpcap.a \
          && install -D -m 644 libpcap.a "/opt/libpcap/$arch/lib/libpcap.a" \
          && echo "INPUT(/opt/libpcap/$arch/lib/libpcap.a)" >"/opt/libpcap/$arch/lib/libpcap.so") \
      || exit 1; \
    done \
 && install -m 644 libpcap-x86_64/LICENSE /opt/libpcap/LICENSE \
 && echo "$LIBPCAP_VERSION" >/opt/libpcap/VERSION \
 && dpkg-query -W -f '${Package}\n' | sort | comm -13 /tmp/packages-before - | xargs apt-get purge -y \
 && rm -rf /tmp/libpcap* /tmp/packages-before "${XDG_CACHE_HOME:-$HOME/.cache}/zig" /var/lib/apt/lists/*

# macOS and Windows release builds (#944), cross-compiled here like the Linux ones
# (docs/ci.md, "macOS and Windows builds"):
# - macOS: the zig above, through cargo-zigbuild and `maturin build --zig`. There
#   is no Apple SDK: zig carries the libSystem link stubs, and the repository's
#   scripts/release/macos-frameworks stand in for the two frameworks the Python
#   extension loads.
# - Windows: the MSVC target, through cargo-xwin (the CLI) and maturin's built-in
#   xwin (the wheels). clang-cl is apt's clang, lld-link is rust-lld, llvm-lib is
#   llvm-tools' llvm-ar (cargo-xwin links both), and nasm assembles AWS-LC.
#   xwin puts Microsoft's CRT and Windows SDK, at the versions pinned below, in
#   /opt/xwin once, from a pinned Visual Studio channel manifest that lists every
#   payload's SHA-256. Building the image accepts Microsoft's licence terms for
#   them (https://go.microsoft.com/fwlink/?LinkId=2086102), which the owner
#   accepted (#944); the image stays in the private registry. XWIN_CACHE_DIR and
#   the DONE file, which lists the architectures cargo-xwin has, make cargo-xwin
#   and maturin use that copy instead of downloading one.
# llvm-tools also brings llvm-objdump and llvm-readobj, which release.yml's
# artifact test runs on the Mach-O and PE files.
ARG CARGO_XWIN_VERSION=0.23.1
ARG CARGO_XWIN_SHA256=c492c6dfb7e5ac0eee586b796e0fc950ba13077e7f0bbb046f445d71790d5360
ARG XWIN_VERSION=0.10.0
ARG XWIN_SHA256=d870eb4b2f390878af6da1ccd3cf321d22fcb72720984853b4be732ae597fc88
# Visual Studio 2022 17.14.41's release channel manifest (aka.ms/vs/17/release/channel
# on 2026-10-01).
ARG VS_CHANNEL_URL=https://download.visualstudio.microsoft.com/download/pr/bc92e2cb-33de-4a0c-995d-efa817f16b16/0dbdfd40c17757e64fc9f72cd9954ec8471c04fd8461a77806e5291e23239ac0/VisualStudio.17.Release.chman
ARG VS_CHANNEL_SHA256=fca418ba94ffbcfb7a2b25f10f16f39dd09660568d21eef4bd3f274cb0b27b8c
ARG MSVC_CRT_VERSION=14.44.17.14
ARG WINDOWS_SDK_VERSION=10.0.26100
ENV XWIN_CACHE_DIR=/opt/xwin \
    XWIN_ARCH=x86_64 \
    XWIN_VARIANT=desktop \
    XWIN_CRT_VERSION=$MSVC_CRT_VERSION \
    XWIN_SDK_VERSION=$WINDOWS_SDK_VERSION
RUN rustup target add --toolchain "$RUST_TOOLCHAIN" \
      x86_64-apple-darwin aarch64-apple-darwin x86_64-pc-windows-msvc \
 && rustup component add --toolchain "$RUST_TOOLCHAIN" llvm-tools \
 && llvm="$(rustup run "$RUST_TOOLCHAIN" rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin" \
 && ln -s "$llvm/llvm-objdump" "$llvm/llvm-readobj" /usr/local/bin/ \
 && apt-get update \
 && apt-get install -y --no-install-recommends clang nasm \
 && rm -rf /var/lib/apt/lists/* \
 && cd /tmp \
 && fetch "https://github.com/rust-cross/cargo-xwin/releases/download/v$CARGO_XWIN_VERSION/cargo-xwin-v$CARGO_XWIN_VERSION.x86_64-unknown-linux-musl.tar.gz" \
      "$CARGO_XWIN_SHA256" cargo-xwin.tgz \
 && tar xzf cargo-xwin.tgz -C "$CARGO_HOME/bin" cargo-xwin \
 && xwin="xwin-$XWIN_VERSION-x86_64-unknown-linux-musl" \
 && fetch "https://github.com/Jake-Shadle/xwin/releases/download/$XWIN_VERSION/$xwin.tar.gz" "$XWIN_SHA256" xwin.tgz \
 && tar xzf xwin.tgz "$xwin/xwin" \
 && fetch "$VS_CHANNEL_URL" "$VS_CHANNEL_SHA256" vs-channel.json \
 && "$xwin/xwin" --accept-license --manifest vs-channel.json --arch x86_64 --variant desktop \
      --crt-version "$MSVC_CRT_VERSION" --sdk-version "$WINDOWS_SDK_VERSION" --cache-dir /tmp/xwin-cache \
      splat --output "$XWIN_CACHE_DIR/xwin" \
 && echo x86_64 >"$XWIN_CACHE_DIR/xwin/DONE" \
 && rm -rf /tmp/cargo-xwin.tgz /tmp/xwin.tgz "/tmp/$xwin" /tmp/vs-channel.json /tmp/xwin-cache \
 && cargo xwin --version && clang --version | head -1 && nasm -v \
 && llvm-objdump --version | head -2 && llvm-readobj --version | head -2 \
 && du -sh "$XWIN_CACHE_DIR"

# The artifact test in release.yml: uv installs the other CPython versions the
# wheels are built for (uv pins each download's SHA-256), and qemu's user-mode
# aarch64 emulator runs the arm64 CLI against the aarch64 glibc of
# libc6-arm64-cross. Only qemu-aarch64-static is taken from Ubuntu's
# qemu-user-static, which installs 130 MB of emulators.
ARG UV_VERSION=0.12.21
ARG UV_SHA256=d69d543a55ec9cdf9d3d9f2648b0a161847e3dbddc477e3be6b5813a6d46f639
RUN cd /tmp \
 && fetch "https://github.com/astral-sh/uv/releases/download/$UV_VERSION/uv-x86_64-unknown-linux-musl.tar.gz" \
      "$UV_SHA256" uv.tgz \
 && tar xzf uv.tgz -C /usr/local/bin --strip-components=1 uv-x86_64-unknown-linux-musl/uv \
 && rm uv.tgz \
 && apt-get update \
 && apt-get install -y --no-install-recommends libc6-arm64-cross \
 && apt-get download qemu-user-static \
 && dpkg-deb --fsys-tarfile qemu-user-static_*.deb \
      | tar -x -C /usr/local/bin --strip-components=3 ./usr/bin/qemu-aarch64-static \
 && rm qemu-user-static_*.deb \
 && rm -rf /var/lib/apt/lists/* \
 && uv --version && qemu-aarch64-static --version >/dev/null
