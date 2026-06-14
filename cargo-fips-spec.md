# cargo-fips — Specification

| | |
|---|---|
| **Status** | Draft v0.1 |
| **Type** | Tooling design specification |
| **Scope** | A Cargo subcommand and companion crate for FIPS 140-3 build assurance and evidence generation in Rust |
| **Audience** | Maintainers and contributors building the tool; downstream teams shipping FIPS-bound Rust applications |

---

## 1. Summary

`cargo-fips` is a **compliance-assurance and evidence tool** for Rust projects that must ship against a FIPS 140-3 validated cryptographic module. It inspects a project's resolved build and verifies four things: that a real validated module is linked, that it is configured in a way that does not silently invalidate it, that the deployment target is a tested (or defensibly vendor-affirmable) operating environment for the module's certificate, and that the result can be captured as machine-readable evidence suitable for a System Security Plan (SSP), an SBOM, or a FedRAMP package.

It is **not** a cryptographic library, **not** a validated module, and **not** a substitute for CMVP validation or an auditor's judgment. It automates plumbing that is performed by hand today and is frequently wrong.

---

## 2. Motivation

FIPS in Rust is currently a collection of working primitives with no connective tissue. A team can link a validated module — via `aws-lc-rs`, the wolfCrypt wrappers, the system OpenSSL 3 FIPS provider, or an HSM over PKCS#11 — but the surrounding obligations remain tribal knowledge: confirming FIPS mode is actually enabled, ensuring no non-validated crypto crate has crept into the dependency graph, keeping build flags from perturbing the validated boundary, matching the runtime operating environment against the certificate, and producing audit evidence. Each is easy to get silently wrong, and each currently has to be reconstructed from scattered vendor blogs, cloud documentation, and certificate Security Policy PDFs.

`cargo-fips` exists to make those obligations mechanical, reviewable, and reproducible.

---

## 3. Goals and Non-Goals

### Goals

- Detect which validated crypto backend(s) a project links, and confirm FIPS mode is actually enabled.
- Detect non-validated cryptographic code reachable in the same build (the "bypass the boundary" failure).
- Classify the target operating environment against a module's certificate: tested, vendor-affirmable, or off-certificate.
- Detect build settings known to perturb a validated module's boundary (e.g., the in-core integrity hash).
- Emit machine-readable attestation (CycloneDX CBOM) and a human-readable compliance summary.
- Provide a runtime companion that asserts FIPS mode and records module identity at application startup.
- Integrate cleanly into CI and container build pipelines.

### Non-Goals

- **Conferring compliance.** The tool surfaces evidence and drift. Vendor affirmation and final sign-off remain human and CMVP judgments, and all output language must reflect this.
- **Implementing cryptography.** No algorithms, no module, and no self-test primitives of its own beyond probing those a backend already provides.
- **Replacing the ground-truth integrity check.** For source-built modules, the recomputed in-core hash remains authoritative; the build-flag guard is defense-in-depth, not a guarantee.
- **Validating a pure-Rust module.** That is a separate lab-and-funding effort (see §4.2). This tool targets the *consumption and attestation* layer.

---

## 4. Background

### 4.1 What FIPS 140-3 validation actually constrains

A FIPS 140-3 validation attaches to a **specific cryptographic module**: a precisely defined code boundary, built by a prescribed procedure, running on a specific tested operating environment, with runtime self-tests (power-on self-tests comprising an integrity check plus known-answer tests, and conditional self-tests including CASTs in 140-3). The certificate's Security Policy enumerates the compiler, compiler settings, build method, tested operating environments, and approved algorithms.

The load-bearing consequence is that **the validated artifact is frozen**: it may not be freely recompiled and still claim validation. Software modules carry an in-core integrity check — commonly an HMAC over the boundary — computed at load, and that value changes when the compiler, flags, or memory layout change. Running on an operating environment not on the certificate is, at best, vendor-affirmed, which is distinct from CMVP-validated and may not satisfy a given procurement.

### 4.2 The current Rust FIPS landscape

Three consumption paths exist today, plus efforts at the edges. (Certificate numbers below are illustrative and must be verified against the live CMVP listing — validations are superseded and operating environments added over time.)

- **Bring your own validated C module** — `aws-lc-rs` (the AWS-LC Cryptographic Module, CMVP cert #4816) or the wolfCrypt wrappers (cert #4718, with #5041 as its evergreen successor). Self-contained and portable, but carries the full build-and-OE burden.
- **Lean on a platform module** — link the system OpenSSL 3 FIPS provider on RHEL/UBI, inheriting the platform vendor's certificate and operating-environment coverage. Commercial equivalents exist (e.g., SafeLogic CryptoComply).
- **Offload entirely** — push crypto to a validated HSM or cloud KMS over PKCS#11, so the application binary contains no validated module.

At the edges, rustls's `CryptoProvider` abstraction exposes a runtime `fips()` status (TLS-only, currently backed by AWS-LC under cert #4816), and there is an in-progress effort to bring a FIPS mode to a pure-Rust module — uncharted territory, because a validated software module has build-freezing requirements no ordinary library has. The pure-Rust providers that exist today (e.g., RustCrypto's rustls provider) are explicitly not validated.

### 4.3 The core problem: an impedance mismatch

Every pain point above is a symptom of one collision. **FIPS validates a frozen artifact** — fixed boundary, build, operating environment, and runtime self-tests. **Cargo's model is the opposite**: build everything from source, with whatever flags the profile selects, for any target, with monomorphization and LTO free to reorganize code. The integrity hash moves because flags move; sources cannot live on crates.io because the validated thing is a controlled artifact; cross-compilation breaks because the operating environment is fixed; and the container-OE question is murky because "operating environment" is not a Cargo concept.

The useful decomposition of 140-3's requirements is into two layers:

- **The frozen-module layer** — boundary, prescribed build, operating environment, integrity check, and known-answer tests. It must be a fixed binary, it fights Cargo's model, and it should be **delegated** to a validated backend.
- **The policy envelope** — approved-algorithms-only, approved parameters, service indicators, key zeroization, self-test status, and compliance evidence. This is what Rust's type system and tooling are good at, and it is almost entirely unbuilt as shared infrastructure.

`cargo-fips` targets the policy envelope and the consumption/attestation plumbing. Its design thesis: **make Rust world-class at consuming and proving validated crypto behind one uniform interface**. That benefits every backend at once and addresses where the great majority of the real pain lives.

---

## 5. Design Principles

1. **Evidence, not absolution.** Output describes what the build asserts and where it diverges from the certificate. It never states that a project "is compliant."
2. **Delegate the frozen layer.** The tool inspects and attests validated modules; it does not reimplement their guarantees.
3. **Data over code.** The reusable value is a curated, machine-readable certificate registry. Mechanism is thin glue around it.
4. **Compose, don't duplicate.** Build attestation on `cargo-cyclonedx`, borrow `cargo-deny`'s config ergonomics, and interoperate with the CBOM ecosystem (e.g., IBM's CBOMkit). Do not reinvent SBOM emission.
5. **CI-first.** Every check is a deterministic gate with a defined exit code.
6. **Backend-extensible.** Supporting a new validated module is a new adapter, not a fork.

---

## 6. Architecture Overview

```
                         fips.toml  (declared intended state)
                              │
        ┌─────────────────────┼─────────────────────────────┐
        ▼                     ▼                              ▼
  cargo fips check     cargo fips oe / guard          cargo fips attest
   (graph + policy)    (environment + build)          (CBOM + summary)
        │                     │                              │
        └─────────┬───────────┴──────────────┬───────────────┘
                  ▼                           ▼
          Backend adapters            FIPS module registry
   (aws-lc-rs, wolfcrypt,          (cert → versions → OEs →
    openssl, pkcs11)                approved algorithms)
                  │
                  ▼
        Runtime companion crate  (startup FIPS assertion + identity log)
```

The components:

- **`fips.toml`** — a declarative manifest of intended state, read by every subcommand.
- **Subcommands** — `check`, `oe`, `guard`, and `attest`.
- **The registry** — a versioned dataset mapping certificates to module versions, tested operating environments, and approved algorithms.
- **Backend adapters** — per-module logic for detection, identity, build parameters, and runtime probing.
- **The runtime companion crate** — bridges build-time assurance to runtime assurance.

---

## 7. Configuration: `fips.toml`

A single, version-controlled manifest at the workspace root. It is to FIPS posture what `deny.toml` is to dependency policy: it turns "are we still FIPS?" into a reviewable artifact.

```toml
[target]
certificate  = "4816"                 # CMVP certificate being claimed
module       = "aws-lc-fips"          # registry module identifier
version      = "AWS-LC-FIPS-2.0"      # pinned validated module version
allowed_oes  = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]
strictness   = "tested-only"          # tested-only | allow-vendor-affirmed

[policy]
forbid_competing_crypto    = true     # fail if a non-validated crypto crate is linked
allowed_backends           = ["aws-lc-rs"]
deny_off_certificate_oe    = true
# optional: restrict to a subset of the certificate's approved algorithms
allowed_algorithms         = []

[attest]
format     = "cyclonedx-cbom-1.6"
output     = "target/fips/attestation.cdx.json"
provenance = true                     # include build provenance (toolchain, git SHA)
sign       = false                    # optional cosign signing

[registry]
source = "builtin"                    # builtin | path | url
# path = "registry/"                  # vendored local registry
```

The manifest is intentionally explicit. Omitting it is a usage error for any command that enforces policy; the tool will not infer an intended certificate.

---

## 8. The FIPS Module Registry

The registry is the heart of the project and its most valuable, hardest-to-build asset. It is the structured form of knowledge currently scattered across Security Policy PDFs and vendor documentation.

### 8.1 Entity model

```
Module
  id, vendor, module_type {software | hybrid},
  security_level, integrity_technique, security_policy_url

Certificate
  cmvp_number, module_id, status {active | historical | revoked},
  validated_versions: [version_string],
  sunset_date

OperatingEnvironment
  id, os, os_version, arch, processor,
  compiler, compiler_flags, paa_enabled  # processor algorithm accelerators

ApprovedAlgorithm
  name, modes: [..], parameters: { key_sizes, curves, ... },
  cavp_certificate, oid

CertificateBinding
  certificate (cmvp_number) →
    tested_operating_environments: [OperatingEnvironment.id],
    approved_algorithms: [ApprovedAlgorithm]
```

### 8.2 Sourcing and maintenance

- **Seeding** is semi-manual curation from each module's Security Policy and the CMVP validated-modules list. There is no clean machine API from NIST for tested operating environments and algorithm sets, which makes this both the project's largest risk and its moat.
- **Contribution model:** vendors (AWS, wolfSSL, Red Hat) are invited to PR their own certificate facts into a dedicated data repository with its own review process.
- **Drift detection:** CI diffs the registry against the CMVP listing to flag superseded versions, newly added operating environments, and sunsets.

### 8.3 Format

Machine-readable (JSON), schema-versioned, distributed with the tool (`source = "builtin"`) and overridable (`path`/`url`) for air-gapped or pre-publication use.

---

## 9. Backend Adapters

Each supported validated module ships an adapter implementing a common trait. Adding a backend is additive.

```rust
/// Implemented per validated module family.
pub trait FipsBackend {
    /// Identify this backend within the resolved dependency graph.
    fn detect(graph: &DependencyGraph) -> Option<DetectedBackend>;

    /// Module name + version + the certificate(s) it maps to.
    fn module_identity(&self, graph: &DependencyGraph) -> ModuleIdentity;

    /// Whether the backend's FIPS mode is actually enabled
    /// (feature flag, provider selection, or sys-crate variant).
    fn fips_enabled(&self, graph: &DependencyGraph) -> FipsModeStatus;

    /// How the boundary is built (prebuilt-static vs source-built),
    /// which determines guard semantics.
    fn build_parameters(&self) -> BuildParameters;

    /// Optional hook the runtime companion uses to probe live FIPS status.
    fn runtime_probe(&self) -> Option<RuntimeProbe>;
}
```

Initial adapters:

| Backend | Module | Boundary | Notes |
|---|---|---|---|
| `aws-lc-rs` | AWS-LC FIPS | prebuilt static | feature `fips`; aligns with Bottlerocket FIPS nodes |
| wolfCrypt wrappers | wolfCrypt FIPS | source-built | in-core hash recomputation; licensed source |
| `openssl` (provider) | OpenSSL 3 FIPS provider | platform-provided | inherits platform OE; UBI/RHEL |
| PKCS#11 backend | external HSM / KMS | out-of-process | sidesteps the build problem entirely |

---

## 10. Subcommands

### 10.1 `cargo fips check`

The primary CI gate. It resolves the dependency graph via `cargo metadata` and the chosen backend adapter, then verifies that:

- A known validated backend is present.
- Its FIPS mode is **actually enabled** — catching the most common silent failure, believing the build is FIPS when the feature is off.
- No second, non-validated cryptographic crate is reachable in the same build (graph analysis catches `ring` or RustCrypto entering via a transitive dependency).
- The declared module/version matches the resolved one; a version that crosses a certificate boundary is flagged.

It fails closed, making it suitable as a required CI job, a pre-commit hook, or a container build stage.

### 10.2 `cargo fips oe`

Operating-environment classification. It resolves the effective target environment (target triple, libc and version, kernel, CPU/PAA features) and classifies it against the certificate binding as:

- **tested** — on the certificate;
- **vendor-affirmable** — module binary unchanged, environment similar but not listed (reported with an explicit caveat);
- **off-certificate** — not defensible without further action (a hard warning, or an error under `deny_off_certificate_oe`).

### 10.3 `cargo fips guard`

Build-flag guard. It inspects the effective `RUSTFLAGS` and the resolved profile (`lto`, `codegen-units`, `opt-level`, `panic`, `target-cpu`/`target-feature`, `strip`) and fails if any setting is known to perturb the validated build. Semantics are per-backend:

- **source-built** (e.g., wolfCrypt) — the concern is the in-core integrity hash shifting; the recomputed hash remains ground truth.
- **prebuilt-static** (e.g., `aws-lc-fips-sys`) — the concern is relinking or altering the validated artifact.

It is positioned explicitly as defense-in-depth, never as a guarantee.

### 10.4 `cargo fips attest`

Evidence generation. It emits a **CycloneDX 1.6 CBOM** (see §11) plus a human-readable summary suitable for an SP 800-53 SC-13 control narrative. Captured fields include module identity and version, the CMVP certificate number and level, the tested operating environment actually used, the approved-algorithm set, the integrity technique, and build provenance. The output can optionally be wrapped in in-toto/SLSA provenance and signed with cosign.

### 10.5 Runtime companion crate

A small library plus macro (a separate crate, e.g., `cargo-fips-runtime`) that, at application startup, asserts the loaded module is in FIPS mode and its power-on self-test passed, then records module identity and service-indicator status. This closes the loop between "built FIPS" and "running FIPS," since FIPS is also a runtime property. It is the meeting point with a future unified provider trait, where `is_fips()` becomes the hook.

### 10.6 Exit code convention

| Code | Meaning |
|---|---|
| `0` | Pass — no policy violation detected |
| `1` | Policy violation — drift from declared state |
| `2` | Configuration or usage error (e.g., missing `fips.toml`) |
| `3` | Registry data unavailable for the requested certificate |

---

## 11. Attestation Format (CycloneDX CBOM)

CycloneDX 1.6 (April 2024) introduced the crypto-properties extension, which models cryptographic assets — algorithms with parameters, modules and libraries, certificates, protocols, and related material — as components and their relationships. Its certification metadata already includes the execution environment and certification level (e.g., FIPS 140-3), which makes it the correct, interoperable target rather than a bespoke format.

The conceptual mapping (implementers follow the upstream CycloneDX CBOM schema for exact field names):

- The validated module → a component carrying crypto-properties of asset type `certificate`/`related-crypto-material`, with the CMVP certificate number, certification level, and execution environment.
- Each approved algorithm → a crypto-asset component with variant/mode, parameters (key sizes, curves), and OID where available.
- Build provenance → standard CycloneDX metadata (tools, timestamps) plus an optional in-toto/SLSA wrapper.

The output is embeddable in a broader SBOM or emitted as a separate linked artifact, and it interoperates with existing CBOM tooling and container scanners.

---

## 12. Integration

- **CI** — `cargo fips check` (and optionally `oe`/`guard`) as a required job that fails the pipeline on drift.
- **Container builds** — run `check` + `guard` in the build stage, then write the `attest` CBOM into the image as an OCI artifact or label so the running container carries its own evidence. This matters because of the platform/application split on managed Kubernetes: cluster-level FIPS (OpenShift install-time mode; EKS FIPS node images such as Bottlerocket FIPS; AKS FIPS node pools) covers only the host and platform components and does **not** validate the application's crypto — which is exactly the application-layer obligation this tool assures.
- **Composition** — adopt `cargo-deny`-style config ergonomics, build attestation on `cargo-cyclonedx`, and pair with `cargo-auditable` for embedded dependency info.
- **Lockfile awareness** — warn when a dependency bump moves the module across a certificate boundary, mirroring published guidance to pin validated module versions.

---

## 13. Implementation Roadmap

| Phase | Deliverable | Notes |
|---|---|---|
| **0 — Spike** | `cargo fips check` for one backend (`aws-lc-rs`), one OE (`x86_64-unknown-linux-gnu`): presence + FIPS feature on + no competing crypto crate | Proves the `cargo metadata` graph analysis; the smallest useful thing |
| **1 — Registry + `oe`** | Registry schema, seeded with the handful of certificates that matter; environment classification | Data-heavy phase; the moat |
| **2 — `guard`** | Per-backend flag-perturbation detection | Test against actual hash changes (wolfCrypt) and known-good configs (AWS-LC) |
| **3 — `attest`** | CycloneDX CBOM emission via `cargo-cyclonedx`; SSP text; optional signing | |
| **4 — Runtime** | Companion crate; tie-in to a unified provider trait | Bridges build-time and runtime assurance |
| **Stretch** | Windows/macOS OEs; `cargo fips init` scaffolder; policy presets (FedRAMP, CNSA); CBOMkit interop | |

**Highest-signal first step:** Phase 0 plus the registry schema for a single certificate (#4816). That slice proves the graph analysis works *and* forces formalization of the OE/algorithm data model the rest of the ecosystem is also missing.

### Contribution strategy

The culture rewards *show, then discuss, then integrate*:

1. Ship `cargo-fips` standalone first — its own repo, dual MIT/Apache license, green CI, and real docs. A Cargo subcommand needs no one's permission.
2. Approach the existing crates (`aws-lc-rs`, rustls, the wolfCrypt wrappers) with a working artifact to point at, and file issues proposing integration hooks (runtime `is_fips()`, version/OE introspection) rather than surprise PRs.
3. Float the unified provider trait as an RFC-style design discussion in RustCrypto/rustls — motivation, alternatives, and drawbacks laid out honestly — before any code.
4. Treat anything requiring a Cargo change (e.g., per-dependency build-flag locking) as an RFC and a multi-month effort; do not make the tool depend on landing one.

---

## 14. Risks and Open Questions

- **Registry maintenance.** Manual curation from PDFs with no NIST API; it rots without vendor participation. Mitigation: vendor PRs plus CMVP diff CI.
- **Vendor affirmation is a judgment, not a binary.** The tool informs; it cannot decide. Output must say so.
- **The guard cannot be exhaustive.** Unknown flag interactions may perturb a boundary. The recomputed hash is ground truth.
- **Reproducible builds are a precondition** for some checks, and Rust is not fully reproducible in all configurations. This ties to broader enabling work.
- **Certificate numbers and OE lists change** as modules are re-validated. Examples in this document are illustrative and must be verified against the live CMVP listing and each module's Security Policy.

---

## 15. Security Considerations

- **Not a compliance oracle.** The single most important framing: a green `check` means "no detected drift from the declared, validated configuration," not "validated." Every surface — CLI output, generated summaries, docs — must preserve this distinction.
- **Registry integrity.** The registry is security-relevant data. It should be signed and verifiable, and the tool should record which registry version produced a given attestation.
- **Attestation integrity.** Signed attestations (cosign/in-toto) prevent post-hoc tampering with evidence artifacts.
- **No secret handling.** The tool inspects build configuration and dependency graphs; it does not touch keys, credentials, or the contents of validated modules.

---

## 16. Governance, Licensing, and Project Home

- **License:** dual MIT/Apache-2.0 (the ecosystem default).
- **Home:** incubate as a standalone project, and engage the RustCrypto org and the `aws-lc-rs`/rustls maintainers early. Keep the registry as a separate data repository so vendors have a clean place to contribute certificate facts.
- **Decision-making:** issue-first for design; RFC-style write-ups for anything cross-cutting (e.g., the provider trait).

---

## Appendix A: Example `fips.toml`

```toml
[target]
certificate = "4816"
module      = "aws-lc-fips"
version     = "AWS-LC-FIPS-2.0"
allowed_oes = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]
strictness  = "tested-only"

[policy]
forbid_competing_crypto = true
allowed_backends        = ["aws-lc-rs"]
deny_off_certificate_oe = true

[attest]
format     = "cyclonedx-cbom-1.6"
output     = "target/fips/attestation.cdx.json"
provenance = true
sign       = false

[registry]
source = "builtin"
```

## Appendix B: Example registry entry (illustrative)

```json
{
  "module": {
    "id": "aws-lc-fips",
    "vendor": "Amazon Web Services",
    "module_type": "software",
    "security_level": 1,
    "integrity_technique": "HMAC-SHA-256",
    "security_policy_url": "https://csrc.nist.gov/..."
  },
  "certificate": {
    "cmvp_number": "4816",
    "status": "active",
    "validated_versions": ["AWS-LC-FIPS-2.0"],
    "sunset_date": "2029-09-30"
  },
  "binding": {
    "tested_operating_environments": [
      { "os": "Amazon Linux", "os_version": "2", "arch": "x86_64",
        "processor": "Intel Xeon", "compiler": "clang", "paa_enabled": true }
    ],
    "approved_algorithms": [
      { "name": "AES", "modes": ["GCM", "CBC"], "parameters": { "key_sizes": [128, 256] }, "cavp_certificate": "Axxxx" },
      { "name": "SHA2", "modes": ["256", "384", "512"], "cavp_certificate": "Axxxx" },
      { "name": "ECDSA", "parameters": { "curves": ["P-256", "P-384"] }, "cavp_certificate": "Axxxx" }
    ]
  }
}
```

## Appendix C: Example `cargo fips check` output (illustrative)

```
cargo fips check  —  certificate #4816 (AWS-LC FIPS), tested-only

  ✓ validated backend detected: aws-lc-rs (feature "fips" enabled)
  ✓ module version resolved: AWS-LC-FIPS-2.0 (matches fips.toml)
  ✓ no competing cryptographic crate reachable in build graph
  ✗ operating environment: aarch64-unknown-linux-gnu is VENDOR-AFFIRMABLE,
      not on certificate #4816's tested list (strictness = tested-only)

  result: FAIL (exit 1) — 1 policy violation
  note: this result reflects drift from your declared validated
        configuration. It is not a determination of FIPS compliance.
```

## Appendix D: Glossary

- **CMVP** — Cryptographic Module Validation Program (NIST/CCCS); issues FIPS 140-3 certificates.
- **CAVP** — Cryptographic Algorithm Validation Program; validates individual algorithms.
- **Operating environment (OE)** — the OS + processor (+ build) combination a module was tested on.
- **POST** — power-on self-test (integrity check + known-answer tests run at load).
- **CAST** — conditional algorithm self-test (140-3).
- **Service indicator** — a 140-3 mechanism by which a module reports whether a service used approved security functions.
- **Vendor affirmation** — a vendor's assertion that an unchanged module runs correctly on an OE not on its certificate; distinct from CMVP validation.
- **CBOM** — Cryptography Bill of Materials (CycloneDX 1.6); a structured inventory of cryptographic assets.
- **Security Policy** — the per-certificate document enumerating boundary, build, OEs, and approved algorithms.
