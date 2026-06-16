# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `cargo fips init` — scaffold a `fips.toml` by detecting the backend in the
  resolved dependency graph, pre-filling the module, certificate, validated
  version, and the certificate's tested operating environments from the registry.
- `cargo fips check` — primary CI gate for the `aws-lc-rs` backend: validated
  backend detection, FIPS-mode verification, competing-crypto detection, and
  declared-vs-validated version checks.
- `cargo fips oe` — operating-environment classification (tested /
  vendor-affirmable / off-certificate) from the target triple.
- `cargo fips guard` — build-flag guard over `RUSTFLAGS` and the resolved profile,
  with per-backend severity (source-built vs prebuilt-static).
- `cargo fips attest` — CycloneDX 1.6 CBOM emission plus a draft SP 800-53 SC-13
  control narrative, with optional build provenance (toolchain, git commit) and
  optional cosign signing (key-based offline, or keyless via Sigstore), delegated
  to the cosign binary.
- `cargo-fips-registry` — typed certificate registry; built-in data for CMVP
  certificate #4816 (AWS-LC FIPS), transcribed from the Security Policy. Registry
  files may now hold multiple certificates per module.
- wolfCrypt backend adapter (source-built boundary) + registry entries for CMVP
  #4718 (v5.2.1, CAVP A4308) and #5041 (v5.2.0.1, CAVP A2461), proving the
  adapter model is not vendor-specific and exercising `guard`'s hard-fail path.
- OpenSSL 3 provider backend adapter (platform-provided boundary) + registry
  entry for the RHEL 9 OpenSSL FIPS Provider, CMVP #4857 (3.0.7-395c1a240fbfffd8,
  CAVP A4807). Detects the classic `openssl`/`openssl-sys` bindings, the newer
  `ossl` binding (from kryoptic), and the rustls-over-OpenSSL providers
  (`rustls-ossl` / `rustls-openssl`).
- PKCS#11 backend adapter (out-of-process boundary) for offload to an external
  HSM/KMS, completing all four boundary kinds. `check` now handles backends that
  pin no certificate (the certificate is operator-declared for this path).
- `cargo-fips-runtime` — runtime FIPS-assertion companion: `FipsProbe` trait,
  `NullProbe`, `assert_fips!`, and (behind the `aws-lc-rs` feature) `AwsLcRsProbe`
  calling `aws_lc_rs::try_fips_mode()`.
- `OpenSslProbe` in `cargo-fips-runtime` — asserts OpenSSL FIPS mode at runtime,
  which is where it is actually decided. It *consumes* the status the application's
  OpenSSL binding already exposes (`ossl::is_fips()`, a rustls
  `CryptoProvider::fips()`, or an FFI check) via `from_status(Option<bool>)`, so it
  pulls no new dependency. `check` now reports OpenSSL FIPS mode as
  runtime-determined rather than guessing from the build graph.
- `readiness()` in `cargo-fips-runtime` — a fail-closed readiness decision over any
  `FipsProbe` for wiring into a `/healthz`/readiness probe. Ready only when FIPS is
  provably active (`Disabled` and `Unknown` are both not-ready), so an orchestrator
  drains traffic from instances that cannot prove FIPS. Dependency-free.
- `record()` in `cargo-fips-runtime` (behind the new `tracing` feature) — emits the
  runtime FIPS status as a structured `tracing` event at startup, severity tracking
  the state, for audit trails and log-based alerting without a new metrics pipeline.
- CI workflow: build, test, and exit-code assertions against fixtures. The
  emitted CBOM is validated against the official CycloneDX 1.6 JSON schema, and
  the CBOM now declares its `$schema`.
