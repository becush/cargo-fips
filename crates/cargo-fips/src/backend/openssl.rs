//! Adapter for the platform-provided OpenSSL 3 FIPS provider
//! (e.g. Red Hat Enterprise Linux 9, CMVP certificate #4857).
//!
//! Applications link the *system* OpenSSL 3 and enable its FIPS provider via
//! platform configuration (`fips=yes` / `OPENSSL_CONF`), inheriting the platform
//! vendor's certificate and operating-environment coverage. The validated module
//! is `fips.so`, supplied by the OS — **not** built from the application's Cargo
//! graph — so the boundary is [`BoundaryKind::PlatformProvided`] and Rust build
//! flags do not perturb it.
//!
//! Detected via the classic `openssl`/`openssl-sys` bindings, the newer `ossl`
//! binding (spun out of the kryoptic project), or a rustls-over-OpenSSL provider
//! (`rustls-ossl` / `rustls-openssl`).
//!
//! FIPS mode here is **purely dynamic** — decided at process start by which
//! providers are loaded and whether the default property query enforces
//! `fips=yes`. The same binary runs FIPS or non-FIPS depending on runtime
//! configuration, so `check` *cannot* prove it from the build and `fips_enabled`
//! reports `Unknown`; the real proof is a runtime assertion (see
//! `cargo-fips-runtime`). What `check` *can* catch is a `vendored` build of the
//! `openssl` crate, which compiles a *separate* OpenSSL and bypasses the platform
//! provider entirely — surfaced here as a distinct signal.

use crate::backend::{
    BoundaryKind, BuildParameters, DetectedBackend, FipsBackend, FipsModeStatus, ModuleIdentity,
};
use crate::metadata::Graph;

/// The platform-provided OpenSSL 3 FIPS provider backend.
pub struct OpenSslProvider;

const ANCHOR: &str = "openssl";
const SYS: &str = "openssl-sys";
/// Crates whose presence indicates this backend: the classic `openssl` bindings,
/// the newer `ossl` binding (from kryoptic), and the rustls-over-OpenSSL providers.
const BINDINGS: &[&str] = &[ANCHOR, SYS, "ossl", "rustls-ossl", "rustls-openssl"];
/// All crates belonging to this backend (bindings plus the vendored-build crate).
const FAMILY: &[&str] = &[
    ANCHOR,
    SYS,
    "ossl",
    "rustls-ossl",
    "rustls-openssl",
    "openssl-src",
];

impl FipsBackend for OpenSslProvider {
    fn name(&self) -> &'static str {
        "openssl"
    }

    fn detect(&self, graph: &Graph) -> Option<DetectedBackend> {
        BINDINGS
            .iter()
            .copied()
            .find(|c| graph.contains(c))
            .map(|c| DetectedBackend {
                name: self.name(),
                anchor_crate: c.to_string(),
            })
    }

    fn module_identity(&self, graph: &Graph) -> ModuleIdentity {
        ModuleIdentity {
            module_id: "rhel9-openssl-fips".to_string(),
            module_crate: BINDINGS
                .iter()
                .copied()
                .find(|c| graph.contains(c))
                .and_then(|c| graph.version_of(c).map(|v| (c.to_string(), v))),
            certificates: vec!["4857".to_string()],
        }
    }

    fn fips_enabled(&self, graph: &Graph) -> FipsModeStatus {
        // A `vendored` OpenSSL is compiled into the binary and is NOT the
        // platform's validated provider — a clear misconfiguration for this path.
        if graph.feature_enabled(ANCHOR, "vendored") || graph.contains("openssl-src") {
            return FipsModeStatus::Disabled;
        }
        // Otherwise FIPS depends on system configuration at runtime, which Cargo
        // cannot observe.
        FipsModeStatus::Unknown
    }

    fn build_parameters(&self) -> BuildParameters {
        BuildParameters {
            boundary: BoundaryKind::PlatformProvided,
        }
    }

    fn own_crates(&self) -> &'static [&'static str] {
        FAMILY
    }
}
