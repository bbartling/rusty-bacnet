# Prebuilt image for the Forgejo CI jobs (#904): the runner's act image plus
# everything the jobs used to install on every run. ci.yml tags it with a hash of
# this file and builds it only when that tag is missing, so any change here, even
# a comment, produces a new tag. Never re-push an existing tag.
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
