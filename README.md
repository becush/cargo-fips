# cargo-fips

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

See [`cargo-fips-spec.md`](./cargo-fips-spec.md) for the full design.

## Status

Early scaffold (Phase 0 + full CLI skeleton).

| Subcommand | Status |
|---|---|
| `cargo fips check` | **implemented** for the `aws-lc-rs` backend |
| `cargo fips oe` | **implemented** (target-triple classification) |
| `cargo fips guard` | **implemented** (RUSTFLAGS + profile inspection) |
| `cargo fips attest` | stub (Phase 3) |
| `cargo-fips-runtime` | API skeleton (Phase 4) |

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
│  └─ modules/aws-lc-fips.json      # built-in registry data (cert #4816)
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

# Run the subcommand against a sample project.
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

## The registry

`registry/modules/*.json` is the curated, machine-readable form of facts
otherwise scattered across CMVP Security Policy PDFs. The shipped
`aws-lc-fips.json` carries **verified** facts for certificate #4816 (module name,
vendor, status, level, validation/sunset dates, Security Policy URL — reviewed
2026-06-14); its tested-OE and algorithm details are seed data to be reconciled
against the Security Policy (see the `_note` field).

## Contributing

Dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE).
Adding a validated module is a new backend adapter (`crates/cargo-fips/src/backend/`)
plus a registry entry — not a fork. Design is issue-first; cross-cutting changes
(e.g. a unified provider trait) are RFC-style write-ups.
