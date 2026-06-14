//! A typed view over `cargo metadata`, plus the competing-crypto heuristic.
//!
//! The key capability is reading the *resolved* feature set per crate
//! (`resolve.nodes[].features`), which is how we tell whether a backend's FIPS
//! feature is actually enabled rather than merely available.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{anyhow, Result};
use cargo_metadata::{Metadata, MetadataCommand, Node, Package, PackageId};

/// A resolved dependency graph for the project under inspection.
pub struct Graph {
    metadata: Metadata,
}

impl Graph {
    /// Run `cargo metadata` for the given manifest (and optional target triple).
    pub fn load(manifest_path: Option<&Path>, target: Option<&str>) -> Result<Self> {
        let mut cmd = MetadataCommand::new();
        if let Some(mp) = manifest_path {
            cmd.manifest_path(mp);
        }
        if let Some(triple) = target {
            // Restrict feature/dep resolution to one platform.
            cmd.other_options(vec!["--filter-platform".to_string(), triple.to_string()]);
        }
        let metadata = cmd
            .exec()
            .map_err(|e| anyhow!("running `cargo metadata`: {e}"))?;
        Ok(Self { metadata })
    }

    /// All resolved packages.
    pub fn packages(&self) -> &[Package] {
        &self.metadata.packages
    }

    /// First package matching a crate name.
    pub fn package_by_name(&self, name: &str) -> Option<&Package> {
        self.metadata.packages.iter().find(|p| p.name == name)
    }

    /// Whether a crate is anywhere in the resolved graph.
    pub fn contains(&self, name: &str) -> bool {
        self.metadata.packages.iter().any(|p| p.name == name)
    }

    /// Resolved version of a crate, as a string.
    pub fn version_of(&self, name: &str) -> Option<String> {
        self.package_by_name(name).map(|p| p.version.to_string())
    }

    /// The resolved node (with enabled features) for a package id.
    fn node(&self, id: &PackageId) -> Option<&Node> {
        self.metadata
            .resolve
            .as_ref()?
            .nodes
            .iter()
            .find(|n| &n.id == id)
    }

    /// The set of features actually enabled for a crate in this resolve.
    pub fn enabled_features(&self, name: &str) -> Option<Vec<String>> {
        let pkg = self.package_by_name(name)?;
        let node = self.node(&pkg.id)?;
        Some(node.features.clone())
    }

    /// Whether a specific feature is enabled for a crate.
    pub fn feature_enabled(&self, name: &str, feature: &str) -> bool {
        self.enabled_features(name)
            .map(|fs| fs.iter().any(|f| f == feature))
            .unwrap_or(false)
    }
}

/// Curated set of crates that provide cryptographic primitives in software and
/// are NOT, by themselves, FIPS-validated. Their presence alongside a validated
/// backend is the "bypass the boundary" risk (spec §10.1).
///
/// This is a deliberately conservative heuristic, not an exhaustive oracle. It
/// lists concrete implementation crates and avoids pure-trait crates
/// (`digest`, `signature`, `crypto-common`, ...) to limit false positives.
pub const KNOWN_COMPETING_CRYPTO: &[&str] = &[
    // C bindings / vendored C (non-FIPS variants)
    "ring",
    "openssl",
    "openssl-sys",
    "boring",
    "boring-sys",
    "libsodium-sys",
    "sodiumoxide",
    // RustCrypto symmetric / AEAD
    "aes",
    "aes-gcm",
    "aes-gcm-siv",
    "aes-siv",
    "chacha20",
    "chacha20poly1305",
    "salsa20",
    "poly1305",
    "ghash",
    // RustCrypto hashes / MAC
    "sha1",
    "sha2",
    "sha3",
    "md-5",
    "md4",
    "hmac",
    "blake2",
    // RustCrypto asymmetric
    "rsa",
    "dsa",
    "ed25519-dalek",
    "x25519-dalek",
    "curve25519-dalek",
    "p256",
    "p384",
    "p521",
    "k256",
    // other crypto stacks
    "rust-crypto",
    "orion",
    "dryoc",
];

/// Competing crypto crates present in the graph, excluding anything in `allow`.
pub fn competing_crates<'a>(graph: &'a Graph, allow: &[String]) -> Vec<&'a str> {
    let allow_set: HashSet<&str> = allow.iter().map(|s| s.as_str()).collect();
    let mut found: Vec<&str> = graph
        .packages()
        .iter()
        .map(|p| p.name.as_str())
        .filter(|n| KNOWN_COMPETING_CRYPTO.contains(n))
        .filter(|n| !allow_set.contains(n))
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}
