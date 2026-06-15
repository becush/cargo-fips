//! Adapter for the wolfCrypt FIPS module via the wolfSSL Rust crates
//! (CMVP certificates #4718 and #5041).
//!
//! Unlike `aws-lc-rs`, wolfCrypt's FIPS status is a property of the linked C
//! build (the licensed FIPS bundle), which Cargo cannot always observe — so
//! `fips_enabled` reports `Unknown` when there is no positive cargo-visible
//! signal, rather than a false `Disabled`. The boundary is **source-built**, so
//! `guard` treats boundary-perturbing build flags as hard failures.

use crate::backend::{
    BoundaryKind, BuildParameters, DetectedBackend, FipsBackend, FipsModeStatus, ModuleIdentity,
};
use crate::metadata::Graph;

/// The wolfCrypt backend.
pub struct WolfCrypt;

/// wolfCrypt-family crates, most specific first. `wolfssl-wolfcrypt` is the
/// official wolfSSL crate with FIPS support.
const FAMILY: &[&str] = &[
    "wolfssl-wolfcrypt",
    "wolfcrypt-rs",
    "wolfssl",
    "wolfssl-sys",
];

impl FipsBackend for WolfCrypt {
    fn name(&self) -> &'static str {
        "wolfcrypt"
    }

    fn detect(&self, graph: &Graph) -> Option<DetectedBackend> {
        FAMILY
            .iter()
            .copied()
            .find(|c| graph.contains(c))
            .map(|c| DetectedBackend {
                name: self.name(),
                anchor_crate: c.to_string(),
            })
    }

    fn module_identity(&self, graph: &Graph) -> ModuleIdentity {
        let anchor = FAMILY.iter().copied().find(|c| graph.contains(c));
        ModuleIdentity {
            module_id: "wolfcrypt".to_string(),
            module_crate: anchor.and_then(|c| graph.version_of(c).map(|v| (c.to_string(), v))),
            certificates: vec!["4718".to_string(), "5041".to_string()],
        }
    }

    fn fips_enabled(&self, graph: &Graph) -> FipsModeStatus {
        // A `fips` feature on the binding is a positive signal; its absence is
        // inconclusive (the underlying C library build is the real determinant),
        // so report Unknown rather than Disabled.
        match FAMILY.iter().copied().find(|c| graph.contains(c)) {
            Some(c) if graph.feature_enabled(c, "fips") => FipsModeStatus::Enabled,
            _ => FipsModeStatus::Unknown,
        }
    }

    fn build_parameters(&self) -> BuildParameters {
        BuildParameters {
            boundary: BoundaryKind::SourceBuilt,
        }
    }

    fn own_crates(&self) -> &'static [&'static str] {
        FAMILY
    }
}
