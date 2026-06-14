//! Adapter for `aws-lc-rs` backed by the AWS-LC FIPS module (cert #4816).

use crate::backend::{
    BoundaryKind, BuildParameters, DetectedBackend, FipsBackend, FipsModeStatus, ModuleIdentity,
};
use crate::metadata::Graph;

/// The `aws-lc-rs` backend.
pub struct AwsLcRs;

/// The Rust binding crate.
const ANCHOR: &str = "aws-lc-rs";
/// `sys` crate pulled in when the `fips` feature is on.
const FIPS_SYS: &str = "aws-lc-fips-sys";
/// `sys` crate pulled in for the non-FIPS build.
const NONFIPS_SYS: &str = "aws-lc-sys";

impl FipsBackend for AwsLcRs {
    fn name(&self) -> &'static str {
        "aws-lc-rs"
    }

    fn detect(&self, graph: &Graph) -> Option<DetectedBackend> {
        if graph.contains(ANCHOR) {
            Some(DetectedBackend {
                name: self.name(),
                anchor_crate: ANCHOR.to_string(),
            })
        } else {
            None
        }
    }

    fn module_identity(&self, graph: &Graph) -> ModuleIdentity {
        // Prefer the FIPS sys-crate (which vendors the validated module); fall
        // back to the binding crate when FIPS is off.
        let module_crate = graph
            .version_of(FIPS_SYS)
            .map(|v| (FIPS_SYS.to_string(), v))
            .or_else(|| graph.version_of(ANCHOR).map(|v| (ANCHOR.to_string(), v)));
        ModuleIdentity {
            module_id: "aws-lc-fips".to_string(),
            module_crate,
            certificates: vec!["4816".to_string()],
        }
    }

    fn fips_enabled(&self, graph: &Graph) -> FipsModeStatus {
        // Strongest signal: enabling `fips` on aws-lc-rs swaps the sys crate
        // aws-lc-sys -> aws-lc-fips-sys, so its presence means FIPS is on.
        if graph.contains(FIPS_SYS) {
            return FipsModeStatus::Enabled;
        }
        // Corroborating signal from the resolved feature set.
        if graph.feature_enabled(ANCHOR, "fips") {
            return FipsModeStatus::Enabled;
        }
        // aws-lc-rs is present but without the FIPS sys crate/feature.
        if graph.contains(NONFIPS_SYS) || graph.contains(ANCHOR) {
            return FipsModeStatus::Disabled;
        }
        FipsModeStatus::Unknown
    }

    fn build_parameters(&self) -> BuildParameters {
        BuildParameters {
            boundary: BoundaryKind::PrebuiltStatic,
        }
    }
}
