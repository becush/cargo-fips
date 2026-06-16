#!/usr/bin/env bash
#
# preflight.sh — the full local gate to run before committing.
#
# Mirrors CI: formatting, lints, tests, and the offline subcommand exit-code
# checks. The networked end-to-end steps (`check`/`attest`, CBOM schema
# validation, and cosign sign/verify) run in CI, so this stays fast and works
# offline.
#
# Usage:  ./scripts/preflight.sh
set -euo pipefail

cd "$(dirname "$0")/.."

bold() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

bold "rustfmt — cargo fmt --all --check"
cargo fmt --all --check

bold "clippy — -D warnings"
cargo clippy --workspace --all-targets -- -D warnings

bold "tests — cargo test --workspace"
cargo test --workspace

# The runtime `tracing` feature is off by default, so exercise it explicitly to
# keep `record()` compiling. (We avoid `--all-features`, which would pull the
# aws-lc-rs FIPS backend and its C/Go toolchain.)
bold "tests — cargo-fips-runtime --features tracing"
cargo test -p cargo-fips-runtime --features tracing

bold "build cargo-fips (for exit-code checks)"
cargo build -q -p cargo-fips
FIPS="target/debug/cargo-fips"

# expect_exit <wanted-code> <command...>
expect_exit() {
  local want="$1"; shift
  set +e; "$@" >/dev/null 2>&1; local got=$?; set -e
  if [ "$got" -ne "$want" ]; then
    printf '   \033[31mFAIL\033[0m exit %s (wanted %s): %s\n' "$got" "$want" "$*"
    exit 1
  fi
  printf '   ok exit %s: %s\n' "$got" "$*"
}

bold "offline subcommand exit codes (oe / guard)"
PASS=fixtures/pass-aws-lc-fips/Cargo.toml
# oe: a tested OE passes; a same-OS-family but unlisted triple is
# vendor-affirmable, which fails under strictness = tested-only.
expect_exit 0 "$FIPS" fips oe --target x86_64-unknown-linux-gnu  --manifest-path "$PASS"
expect_exit 1 "$FIPS" fips oe --target x86_64-unknown-linux-musl --manifest-path "$PASS"
# guard: a perturbing flag hard-fails a source-built boundary, but is N/A (pass)
# for platform-provided and out-of-process boundaries.
expect_exit 1 env RUSTFLAGS="-C target-cpu=native" "$FIPS" fips guard --manifest-path fixtures/guard-wolfcrypt/Cargo.toml
expect_exit 0 env RUSTFLAGS="-C target-cpu=native" "$FIPS" fips guard --manifest-path fixtures/guard-openssl/Cargo.toml
expect_exit 0 env RUSTFLAGS="-C target-cpu=native" "$FIPS" fips guard --manifest-path fixtures/guard-pkcs11/Cargo.toml

printf '\n\033[32mpreflight passed\033[0m\n'
