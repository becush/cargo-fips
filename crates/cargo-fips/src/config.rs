//! Parsing of `fips.toml` (spec §7).

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use cargo_fips_registry::Registry;
use serde::Deserialize;

/// The full `fips.toml` manifest.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FipsConfig {
    pub target: Target,
    #[serde(default)]
    pub policy: Policy,
    #[serde(default)]
    #[allow(dead_code)] // consumed by `cargo fips attest` (Phase 3)
    pub attest: Attest,
    #[serde(default)]
    pub registry: RegistrySource,
}

/// `[target]` — the certificate and module being claimed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub certificate: String,
    pub module: String,
    pub version: String,
    #[serde(default)]
    pub allowed_oes: Vec<String>,
    #[serde(default)]
    pub strictness: Strictness,
}

/// How strictly the operating environment must match the certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Strictness {
    /// Only operating environments on the certificate pass.
    #[default]
    TestedOnly,
    /// Vendor-affirmable environments are allowed (with a caveat).
    AllowVendorAffirmed,
}

impl Strictness {
    pub fn as_str(self) -> &'static str {
        match self {
            Strictness::TestedOnly => "tested-only",
            Strictness::AllowVendorAffirmed => "allow-vendor-affirmed",
        }
    }
}

/// `[policy]` — what to forbid or allow.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub forbid_competing_crypto: bool,
    #[serde(default)]
    pub allowed_backends: Vec<String>,
    #[serde(default)]
    pub deny_off_certificate_oe: bool,
    #[serde(default)]
    #[allow(dead_code)] // consumed by algorithm-subset policy (later)
    pub allowed_algorithms: Vec<String>,
}

/// `[attest]` — evidence output settings.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // fields consumed by `cargo fips attest` (Phase 3)
pub struct Attest {
    #[serde(default = "default_attest_format")]
    pub format: String,
    #[serde(default = "default_attest_output")]
    pub output: PathBuf,
    #[serde(default)]
    pub provenance: bool,
    #[serde(default)]
    pub sign: bool,
}

impl Default for Attest {
    fn default() -> Self {
        Self {
            format: default_attest_format(),
            output: default_attest_output(),
            provenance: false,
            sign: false,
        }
    }
}

fn default_attest_format() -> String {
    "cyclonedx-cbom-1.6".to_string()
}

fn default_attest_output() -> PathBuf {
    PathBuf::from("target/fips/attestation.cdx.json")
}

/// `[registry]` — where to load certificate data from.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySource {
    /// `builtin` | `path` | `url`.
    #[serde(default = "default_registry_source")]
    pub source: String,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    #[allow(dead_code)] // `source = "url"` registry loading (Phase 1+)
    pub url: Option<String>,
}

impl Default for RegistrySource {
    fn default() -> Self {
        Self {
            source: default_registry_source(),
            path: None,
            url: None,
        }
    }
}

fn default_registry_source() -> String {
    "builtin".to_string()
}

impl FipsConfig {
    /// Load `fips.toml` from an explicit path, or `<manifest_dir>/fips.toml`.
    ///
    /// Returns the parsed config and the path it was read from.
    pub fn load(explicit: Option<&Path>, manifest_dir: &Path) -> Result<(Self, PathBuf)> {
        let path = match explicit {
            Some(p) => p.to_path_buf(),
            None => manifest_dir.join("fips.toml"),
        };
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let config: FipsConfig =
            toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
        Ok((config, path))
    }

    /// Resolve the certificate registry per `[registry]` in `fips.toml`.
    pub fn load_registry(&self, manifest_dir: &Path) -> Result<Registry> {
        match self.registry.source.as_str() {
            "builtin" => Ok(Registry::builtin()?),
            "path" => {
                let path = self
                    .registry
                    .path
                    .clone()
                    .ok_or_else(|| anyhow!("[registry] source = \"path\" requires `path`"))?;
                let dir = if path.is_absolute() {
                    path
                } else {
                    manifest_dir.join(path)
                };
                Ok(Registry::from_path(&dir)?)
            }
            "url" => Err(anyhow!(
                "[registry] source = \"url\" is not yet implemented (see spec §8.3)"
            )),
            other => Err(anyhow!("unknown [registry] source: {other}")),
        }
    }
}
