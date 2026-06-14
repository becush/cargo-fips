//! Backend adapters (spec §9).
//!
//! Each validated module family implements [`FipsBackend`]. Adding support for a
//! new module is a new adapter, not a fork. This adapts the spec's trait to take
//! `&self` so adapters can be held as trait objects in [`all_backends`].

pub mod aws_lc;

use crate::metadata::Graph;

/// Whether a backend's FIPS mode is actually enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FipsModeStatus {
    Enabled,
    Disabled,
    Unknown,
}

/// A backend located in the dependency graph.
#[derive(Debug, Clone)]
pub struct DetectedBackend {
    /// Adapter name; surfaced in attestation output (Phase 3).
    #[allow(dead_code)]
    pub name: &'static str,
    /// The crate that anchors detection (e.g. `aws-lc-rs`).
    pub anchor_crate: String,
}

/// Identity of the validated module a backend maps to.
#[derive(Debug, Clone)]
pub struct ModuleIdentity {
    /// Registry module id (e.g. `aws-lc-fips`).
    pub module_id: String,
    /// The crate that carries the validated module and its resolved version, as
    /// `(crate_name, version)` — e.g. `("aws-lc-fips-sys", "0.13.14")`.
    pub module_crate: Option<(String, String)>,
    /// CMVP certificate number(s) this backend maps to.
    pub certificates: Vec<String>,
}

/// How the validated boundary is produced, which determines `guard` semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryKind {
    /// Prebuilt static artifact relinked into the binary (e.g. aws-lc-fips-sys).
    PrebuiltStatic,
    /// Compiled from controlled source; in-core hash is recomputed (e.g. wolfCrypt).
    SourceBuilt,
    /// Provided by the platform (e.g. the system OpenSSL 3 FIPS provider).
    #[allow(dead_code)] // constructed by the openssl provider adapter (not yet added)
    PlatformProvided,
    /// External module reached over IPC (e.g. PKCS#11 HSM/KMS).
    #[allow(dead_code)] // constructed by the pkcs11 adapter (not yet added)
    OutOfProcess,
}

impl BoundaryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BoundaryKind::PrebuiltStatic => "prebuilt-static",
            BoundaryKind::SourceBuilt => "source-built",
            BoundaryKind::PlatformProvided => "platform-provided",
            BoundaryKind::OutOfProcess => "out-of-process",
        }
    }
}

/// Build characteristics relevant to boundary integrity.
#[derive(Debug, Clone, Copy)]
pub struct BuildParameters {
    pub boundary: BoundaryKind,
}

/// Implemented per validated module family.
pub trait FipsBackend {
    /// Stable adapter name.
    fn name(&self) -> &'static str;

    /// Identify this backend within the resolved dependency graph.
    fn detect(&self, graph: &Graph) -> Option<DetectedBackend>;

    /// Module id + resolved version + the certificate(s) it maps to.
    fn module_identity(&self, graph: &Graph) -> ModuleIdentity;

    /// Whether the backend's FIPS mode is actually enabled.
    fn fips_enabled(&self, graph: &Graph) -> FipsModeStatus;

    /// How the boundary is built (determines guard semantics).
    fn build_parameters(&self) -> BuildParameters;
}

/// All backend adapters known to the tool.
pub fn all_backends() -> Vec<Box<dyn FipsBackend>> {
    // Explicit cast so the element type is the trait object, not `Box<AwsLcRs>`.
    vec![Box::new(aws_lc::AwsLcRs) as Box<dyn FipsBackend>]
}

/// Every backend that is present in the graph, paired with its detection result.
pub fn detect_backends(graph: &Graph) -> Vec<(Box<dyn FipsBackend>, DetectedBackend)> {
    all_backends()
        .into_iter()
        .filter_map(|b| {
            let detected = b.detect(graph)?;
            Some((b, detected))
        })
        .collect()
}
