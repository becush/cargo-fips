//! The registry entity model.
//!
//! Mirrors §8.1 of the spec. These types are the typed form of the JSON files
//! under `registry/modules/*.json`. Unknown JSON fields are ignored on
//! deserialization (so `_note`, `_sources`, etc. may be used for provenance).

use serde::{Deserialize, Serialize};

/// Whether the validated module is pure software or a hardware/software hybrid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModuleType {
    Software,
    Hybrid,
}

/// CMVP certificate lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertificateStatus {
    Active,
    Historical,
    Revoked,
}

/// A validated cryptographic module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Module {
    /// Registry identifier, e.g. `aws-lc-fips`.
    pub id: String,
    pub vendor: String,
    pub module_type: ModuleType,
    /// FIPS 140-3 overall security level (1-4).
    pub security_level: u8,
    /// e.g. `HMAC-SHA-256` for the in-core integrity check.
    pub integrity_technique: String,
    #[serde(default)]
    pub security_policy_url: Option<String>,
}

/// A CMVP certificate and the module versions it validates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    /// CMVP certificate number, kept as a string (e.g. `"4816"`).
    pub cmvp_number: String,
    pub status: CertificateStatus,
    #[serde(default)]
    pub validated_versions: Vec<String>,
    /// ISO-8601 date (`YYYY-MM-DD`) after which the certificate is moved to the
    /// historical list, if known.
    #[serde(default)]
    pub sunset_date: Option<String>,
}

/// A tested operating environment from a certificate's Security Policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatingEnvironment {
    #[serde(default)]
    pub id: Option<String>,
    pub os: String,
    #[serde(default)]
    pub os_version: Option<String>,
    pub arch: String,
    #[serde(default)]
    pub processor: Option<String>,
    #[serde(default)]
    pub compiler: Option<String>,
    #[serde(default)]
    pub compiler_flags: Option<String>,
    /// Processor algorithm accelerators (e.g. AES-NI) enabled in the tested config.
    #[serde(default)]
    pub paa_enabled: Option<bool>,
    /// Rust target triple(s) that map to this OE, used by `cargo fips oe`.
    #[serde(default)]
    pub target_triples: Vec<String>,
}

/// An approved algorithm with its parameters and CAVP reference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovedAlgorithm {
    pub name: String,
    #[serde(default)]
    pub modes: Vec<String>,
    /// Free-form parameters (key sizes, curves, ...). Kept as raw JSON so the
    /// registry can carry whatever a given algorithm needs without schema churn.
    #[serde(default)]
    pub parameters: serde_json::Value,
    #[serde(default)]
    pub cavp_certificate: Option<String>,
    #[serde(default)]
    pub oid: Option<String>,
}

/// What a certificate binds together: tested OEs and approved algorithms.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CertificateBinding {
    #[serde(default)]
    pub tested_operating_environments: Vec<OperatingEnvironment>,
    #[serde(default)]
    pub approved_algorithms: Vec<ApprovedAlgorithm>,
}

/// One full registry record: a module, the certificate claimed, and its binding.
/// This is the shape of each `registry/modules/*.json` file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryEntry {
    /// Schema version of this record's shape (defaults to 1).
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub module: Module,
    pub certificate: Certificate,
    pub binding: CertificateBinding,
}

fn default_schema_version() -> u32 {
    1
}

impl RegistryEntry {
    /// True if `version` is one of this certificate's validated versions.
    pub fn validates_version(&self, version: &str) -> bool {
        self.certificate
            .validated_versions
            .iter()
            .any(|v| v == version)
    }

    /// Find a tested OE whose `target_triples` contains `triple`.
    pub fn tested_oe_for_triple(&self, triple: &str) -> Option<&OperatingEnvironment> {
        self.binding
            .tested_operating_environments
            .iter()
            .find(|oe| oe.target_triples.iter().any(|t| t == triple))
    }
}
