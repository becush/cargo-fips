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
//! FIPS mode is a runtime/platform property invisible to Cargo, so
//! `fips_enabled` reports `Unknown`. A `vendored` build of the `openssl` crate
//! would compile a *separate* OpenSSL and bypass the platform provider entirely;
//! that is surfaced as a distinct signal.

use crate::backend::{
    BoundaryKind, BuildParameters, DetectedBackend, FipsBackend, FipsModeStatus, ModuleIdentity,
};
use crate::metadata::Graph;

/// The platform-provided OpenSSL 3 FIPS provider backend.
pub struct OpenSslProvider;

const ANCHOR: &str = "openssl";
const SYS: &str = "openssl-sys";
/// All crates belonging to this backend (`openssl-src` is the vendored build).
const FAMILY: &[&str] = &[ANCHOR, SYS, "openssl-src"];

impl FipsBackend for OpenSslProvider {
    fn name(&self) -> &'static str {
        "openssl"
    }

    fn detect(&self, graph: &Graph) -> Option<DetectedBackend> {
        for crate_name in [ANCHOR, SYS] {
            if graph.contains(crate_name) {
                return Some(DetectedBackend {
                    name: self.name(),
                    anchor_crate: crate_name.to_string(),
                });
            }
        }
        None
    }

    fn module_identity(&self, graph: &Graph) -> ModuleIdentity {
        ModuleIdentity {
            module_id: "rhel9-openssl-fips".to_string(),
            module_crate: graph
                .version_of(SYS)
                .map(|v| (SYS.to_string(), v))
                .or_else(|| graph.version_of(ANCHOR).map(|v| (ANCHOR.to_string(), v))),
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
