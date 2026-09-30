# Prebuilt image for the Forgejo CI jobs (#904): the runner's default act image
# plus everything the jobs used to install on every run. The workflow tags the
# image with a hash of this file and builds it only when that tag is missing, so
# any change here produces a new tag. Bump the pins together with ci.yml's env
# and rust-toolchain.toml; the "CI image" job fails if they disagree.
FROM ghcr.io/catthehacker/ubuntu:act-24.04

ARG RUST_TOOLCHAIN=1.97.1
ARG RUST_MSRV=1.93
ARG NEXTEST_VERSION=0.9.146
ARG CARGO_AUDIT_VERSION=0.22.2
ARG CARGO_DENY_VERSION=0.20.2
ARG MATURIN_VERSION=1.15.0

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

# The CI toolchain with the components the jobs use, and the MSRV toolchain.
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal \
      --default-toolchain "$RUST_TOOLCHAIN" -c rustfmt,clippy \
 && rustup toolchain install "$RUST_MSRV" --profile minimal \
 && rustc --version && rustup run "$RUST_MSRV" rustc --version

RUN set -eux; \
    bin="$CARGO_HOME/bin"; \
    curl -sSfL "https://get.nexte.st/$NEXTEST_VERSION/linux" | tar xzf - -C "$bin"; \
    curl -sSfL "https://github.com/EmbarkStudios/cargo-deny/releases/download/$CARGO_DENY_VERSION/cargo-deny-$CARGO_DENY_VERSION-x86_64-unknown-linux-musl.tar.gz" \
      | tar xzf - -C "$bin" --strip-components=1 "cargo-deny-$CARGO_DENY_VERSION-x86_64-unknown-linux-musl/cargo-deny"; \
    curl -sSfL "https://github.com/rustsec/rustsec/releases/download/cargo-audit%2Fv$CARGO_AUDIT_VERSION/cargo-audit-x86_64-unknown-linux-musl-v$CARGO_AUDIT_VERSION.tgz" \
      | tar xzf - -C "$bin" --strip-components=1 "cargo-audit-x86_64-unknown-linux-musl-v$CARGO_AUDIT_VERSION/cargo-audit"; \
    curl -sSfL "https://github.com/PyO3/maturin/releases/download/v$MATURIN_VERSION/maturin-x86_64-unknown-linux-musl.tar.gz" \
      | tar xzf - -C /usr/local/bin maturin; \
    cargo nextest --version; cargo deny --version; cargo audit --version; maturin --version
