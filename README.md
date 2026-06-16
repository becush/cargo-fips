# cargo-fips

[![CI](https://github.com/becush/cargo-fips/actions/workflows/ci.yml/badge.svg)](https://github.com/becush/cargo-fips/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#contributing)
[![Status: experimental](https://img.shields.io/badge/status-experimental%20(v0.0.x)-orange.svg)](#status)

A Cargo subcommand and companion crate for **FIPS 140-3 build assurance and
evidence generation** in Rust.

`cargo-fips` inspects a project's resolved build and checks that it is configured
against a real CMVP-validated cryptographic module in a way that does not
silently invalidate it — then produces machine-readable evidence. It is a
**compliance-assurance and evidence tool**, not a cryptographic library and not a
validated module.

> **Evidence, not absolution.** A green `cargo fips check` means "no detected
> drift from the declared, validated configuration," *not* "validated." Vendor
> affirmation and final sign-off are human and CMVP judgments.

> ⚠️ **Experimental (v0.0.x).** APIs, output, and the registry schema may change.
> The certificate registry mixes CMVP-verified facts with **seed data** (some
> tested-OE and CAVP details); check each entry's `_sources`/`_note` against the
> module's Security Policy before relying on it. Not a basis for a compliance
> decision.

See [`cargo-fips-spec.md`](./cargo-fips-spec.md) for the full design.

## Status

Experimental (v0.0.x): all subcommands are implemented and CI-tested, but the
registry is partly seed data (see the note above), so this isn't yet a basis for
a compliance decision.

| Subcommand | Status |
|---|---|
| `cargo fips init` | **implemented** (scaffold fips.toml from the graph) |
| `cargo fips check` | **implemented** for the `aws-lc-rs` backend |
| `cargo fips oe` | **implemented** (target-triple classification) |
| `cargo fips guard` | **implemented** (RUSTFLAGS + profile inspection) |
| `cargo fips attest` | **implemented** (CycloneDX 1.6 CBOM + SC-13 narrative) |
| `cargo-fips-runtime` | **implemented** (`NullProbe`; `AwsLcRsProbe` via feature) |

What `check` verifies today (spec §10.1):

1. a known validated backend is present in the dependency graph;
2. its FIPS mode is **actually enabled** (for `aws-lc-rs`, that the `fips`
   feature / `aws-lc-fips-sys` is in the resolved graph);
3. no competing, non-validated crypto crate is reachable (a curated heuristic);
4. the declared module/version is validated by the claimed certificate, per the
   built-in registry.

It fails closed and follows a fixed exit-code convention (spec §10.6):

| Code | Meaning |
|---|---|
| `0` | Pass — no policy violation detected |
| `1` | Policy violation — drift from declared state |
| `2` | Configuration or usage error (e.g. missing `fips.toml`) |
| `3` | Registry data unavailable for the requested certificate |

## Workspace layout

```
cargo-fips/
├─ Cargo.toml                       # workspace
├─ cargo-fips-spec.md               # the design spec
├─ registry/
│  └─ modules/                      # built-in registry data
│     ├─ aws-lc-fips.json           #   cert #4816
│     ├─ wolfcrypt.json             #   certs #4718, #5041
│     └─ openssl.json               #   cert #4857 (RHEL 9 provider)
├─ crates/
│  ├─ cargo-fips/                   # the CLI (the `cargo fips` subcommand)
│  ├─ cargo-fips-registry/          # typed registry model + loader (shared lib)
│  └─ cargo-fips-runtime/           # runtime FIPS-assertion companion (lib)
├─ fixtures/                        # sample projects CI runs `check` against
│  ├─ pass-aws-lc-fips/             # → exit 0
│  ├─ fail-fips-off/                # → exit 1
│  └─ fail-competing-crypto/        # → exit 1
└─ .github/workflows/ci.yml         # build + test + e2e exit-code assertions
```

## Quickstart

Requires a stable Rust toolchain (`rustup`), Rust 1.74+.

```sh
# Build and test the workspace (registry + runtime tests need no network).
cargo build --workspace
cargo test  --workspace

# Scaffold a fips.toml by detecting the backend in a project's graph.
cargo run -p cargo-fips -- fips init \
    --manifest-path fixtures/pass-aws-lc-fips/Cargo.toml --output /tmp/fips.toml

# Run the primary gate against a sample project.
cargo run -p cargo-fips -- fips check \
    --manifest-path fixtures/pass-aws-lc-fips/Cargo.toml

# Or install it so it works as a real cargo subcommand:
cargo install --path crates/cargo-fips
cd fixtures/pass-aws-lc-fips && cargo fips check
```

Example output:

```
cargo fips check  —  certificate #4816 (aws-lc-fips), tested-only

  ✓ validated backend detected: aws-lc-rs
  ✓ aws-lc-rs: FIPS mode enabled
  ✓ module version AWS-LC-FIPS-2.0 is validated under certificate #4816
  · resolved aws-lc-rs crate version: 1.x.y
  ✓ no competing cryptographic crate reachable in build graph

  result: PASS (exit 0)
  note: this result reflects drift from your declared validated configuration.
        It is not a determination of FIPS compliance.
```

`cargo fips check` only runs `cargo metadata` (dependency-graph resolution); it
does **not** compile the C-backed crypto crates, so it stays fast and needs no
crypto build toolchain.

### Operating-environment classification

`cargo fips oe` classifies a target triple against the certificate's tested
operating environments. With no `--target`, it evaluates the declared
`allowed_oes`; otherwise the host triple.

```sh
# Both declared OEs (x86_64 + aarch64 Graviton) are tested → clean pass
cargo fips oe --manifest-path fixtures/pass-aws-lc-fips/Cargo.toml

# Same OS family but not listed (musl) → vendor-affirmable (fails under tested-only)
cargo fips oe --target x86_64-unknown-linux-musl \
    --manifest-path fixtures/pass-aws-lc-fips/Cargo.toml
```

```
cargo fips oe  —  certificate #4816 (aws-lc-fips), tested-only
  host target: aarch64-apple-darwin
  evaluating: declared allowed_oes

  ✓ x86_64-unknown-linux-gnu: tested — on certificate #4816
  ✓ aarch64-unknown-linux-gnu: tested — on certificate #4816

  result: PASS (exit 0)
  note: this result reflects drift from your declared validated configuration.
        It is not a determination of FIPS compliance.
```

Unlike `check`, `oe` needs no `cargo metadata` — only `fips.toml`, the registry,
and `rustc` (for host detection).

### Build-flag guard

`cargo fips guard` inspects the effective `RUSTFLAGS` and the resolved
`[profile.<profile>]` (default `release`) and flags settings known to perturb
the validated boundary. Severity is per-backend:

- **source-built** (e.g. wolfCrypt) — hash-shifting settings (`target-cpu`,
  `target-feature`, LTO, …) are hard failures; the recomputed in-core integrity
  hash is ground truth.
- **prebuilt-static** (e.g. `aws-lc-fips-sys`) — the same settings are warnings,
  since Rust flags don't recompile the vendored C artifact.

```sh
# clean build → pass
cargo fips guard --manifest-path fixtures/pass-aws-lc-fips/Cargo.toml

# a perturbing flag against a prebuilt-static backend → warning (still exit 0)
RUSTFLAGS="-C target-cpu=native" \
  cargo fips guard --manifest-path fixtures/pass-aws-lc-fips/Cargo.toml
```

Guard is defense-in-depth, never a guarantee. Like `oe`, it runs offline (no
`cargo metadata`).

### Attestation

`cargo fips attest` emits a [CycloneDX 1.6](https://cyclonedx.org) CBOM —
the validated module plus each approved algorithm as crypto-asset components with
`certificationLevel` — and prints a draft SP 800-53 SC-13 (Cryptographic
Protection) control narrative. Build provenance (toolchain, git commit) is
included when `[attest] provenance = true`.

```sh
cargo fips attest \
    --manifest-path fixtures/pass-aws-lc-fips/Cargo.toml \
    --output target/fips/attestation.cdx.json
```

The CBOM is embeddable in a broader SBOM or shipped as a linked artifact (e.g.
written into a container image). It declares its `$schema`, and CI validates
every emitted CBOM against the official CycloneDX 1.6 JSON schema.

Signing is delegated to [cosign](https://github.com/sigstore/cosign) (the tool
does not reimplement signing). Set `[attest] sign = true` or pass `--sign`:

```sh
# key-based, offline (no transparency-log upload)
cargo fips attest --manifest-path . --sign --cosign-key cosign.key
# keyless (Sigstore/Fulcio + Rekor) when no key is given — needs ambient OIDC
cargo fips attest --manifest-path . --sign
```

This writes a detached `*.sig` next to the CBOM (plus a certificate and bundle in
keyless mode). CI signs with an ephemeral key and verifies the result with
`cosign verify-blob`.

### Runtime assertion (`cargo-fips-runtime`)

`check`/`oe`/`guard`/`attest` prove a build *was configured* for FIPS. FIPS is
also a *runtime* property, so the companion crate asserts it at startup. The
default build is dependency-free (`NullProbe` → `Unknown`); enable the `aws-lc-rs`
feature for a real probe that calls `aws_lc_rs::try_fips_mode()`:

```toml
[dependencies]
cargo-fips-runtime = { version = "0.0.1", features = ["aws-lc-rs"] }
```

```rust
use cargo_fips_runtime::{assert_fips, AwsLcRsProbe, OnFailure};

fn main() {
    // Aborts startup unless the linked AWS-LC is in FIPS-approved mode.
    assert_fips!(AwsLcRsProbe, OnFailure::Panic);
}
```

`FipsProbe` is the integration point a future unified provider trait (`is_fips()`)
would implement. The `aws-lc-rs` feature pulls aws-lc-rs's FIPS backend, which
needs a C toolchain (cmake, a C compiler, Go) to build.

## Configuration: `fips.toml`

A version-controlled manifest at the project root declares the intended FIPS
posture. See spec §7 and the fixtures for examples.

```toml
[target]
certificate = "4816"
module      = "aws-lc-fips"
version     = "AWS-LC-FIPS-2.0"
strictness  = "tested-only"

[policy]
forbid_competing_crypto = true
allowed_backends        = ["aws-lc-rs"]

[registry]
source = "builtin"
```

## Backends and the registry

Four backend adapters ship today, covering **every boundary kind in the spec**:

| Backend | Module | Boundary | Certificate(s) |
|---|---|---|---|
| `aws-lc-rs` | AWS-LC FIPS | prebuilt-static | #4816 |
| wolfSSL Rust crates | wolfCrypt FIPS | source-built | #4718, #5041 |
| `openssl` (system provider) | RHEL 9 OpenSSL FIPS provider | platform-provided | #4857 |
| `cryptoki` / PKCS#11 | external HSM / KMS | out-of-process | operator-declared |

The boundary kind drives `guard`. For the same perturbing flag (`-C target-cpu`):

- **prebuilt-static** (AWS-LC) → **warning** (the vendored artifact isn't recompiled);
- **source-built** (wolfCrypt) → **hard failure** (it would shift the in-core integrity hash);
- **platform-provided** (OpenSSL provider) → **not applicable** (the OS-supplied `fips.so` is untouched) → pass;
- **out-of-process** (PKCS#11 HSM/KMS) → **not applicable** (no validated module in the binary) → pass.

`registry/modules/*.json` is the curated, machine-readable form of facts
otherwise scattered across CMVP Security Policy PDFs (one file may hold multiple
certificates for a module). The shipped data carries **verified** facts —
reviewed 2026-06-14 — for AWS-LC #4816; wolfCrypt #4718 (v5.2.1, CAVP A4308) and
#5041 (v5.2.0.1, CAVP A2461); and the RHEL 9 OpenSSL FIPS provider #4857
(3.0.7-395c1a240fbfffd8, CAVP A4807). Each entry has `_sources` provenance and a
dated `_note`; where a full Security Policy table wasn't transcribed, the `_note`
says so.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the full guide. In short: format with
`cargo fmt`, keep `clippy` clean, document public items, and sign off every commit
(`git commit -s`, per the [DCO](./DCO)). Security reports go through
[SECURITY.md](./SECURITY.md).

Dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE).
Adding a validated module is a new backend adapter (`crates/cargo-fips/src/backend/`)
plus a registry entry — not a fork. Design is issue-first; cross-cutting changes
(e.g. a unified provider trait) are RFC-style write-ups.
