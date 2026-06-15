//! Adapter for offloading crypto to an external validated module over PKCS#11
//! (an HSM or cloud KMS), via Rust PKCS#11 client crates such as `cryptoki`.
//!
//! Here the application binary contains **no** validated module: cryptography
//! runs out-of-process in a hardware/managed module. The boundary is
//! [`BoundaryKind::OutOfProcess`], so Rust build flags are irrelevant to it, and
//! the relevant CMVP certificate is the *deployed* device's — declared by the
//! operator in `fips.toml`, not inferable from the Cargo graph (so this adapter
//! pins no certificate). FIPS status is a property of the token, checked at
//! runtime, so `fips_enabled` is `Unknown`.

use crate::backend::{
    BoundaryKind, BuildParameters, DetectedBackend, FipsBackend, FipsModeStatus, ModuleIdentity,
};
use crate::metadata::Graph;

/// The PKCS#11 (external HSM / KMS) backend.
pub struct Pkcs11;

/// PKCS#11 client crates, most common first. `cryptoki` is the modern,
/// widely-used safe binding.
const FAMILY: &[&str] = &["cryptoki", "cryptoki-sys", "pkcs11"];

impl FipsBackend for Pkcs11 {
    fn name(&self) -> &'static str {
        "pkcs11"
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
        ModuleIdentity {
            module_id: "pkcs11-external".to_string(),
            module_crate: FAMILY
                .iter()
                .copied()
                .find(|c| graph.contains(c))
                .and_then(|c| graph.version_of(c).map(|v| (c.to_string(), v))),
            // The validated module is the external HSM/KMS; its certificate is
            // deployment-specific and declared by the operator, not inferable here.
            certificates: Vec::new(),
        }
    }

    fn fips_enabled(&self, _graph: &Graph) -> FipsModeStatus {
        // FIPS status is a property of the external token, observable only at
        // runtime (e.g. via the runtime companion querying the token).
        FipsModeStatus::Unknown
    }

    fn build_parameters(&self) -> BuildParameters {
        BuildParameters {
            boundary: BoundaryKind::OutOfProcess,
        }
    }

    fn own_crates(&self) -> &'static [&'static str] {
        FAMILY
    }
}
