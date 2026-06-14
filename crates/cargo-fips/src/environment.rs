//! Operating-environment resolution and classification (spec §10.2).
//!
//! Phase 1 keys off the Rust **target triple**: it is resolved (from `--target`
//! or the host) and classified against a certificate's tested operating
//! environments. Richer signals the spec mentions — libc version, kernel,
//! CPU/PAA features — are future refinements; the triple gives arch + OS family,
//! which is enough to reproduce the tested / vendor-affirmable / off-certificate
//! distinction.

use std::process::Command;

use cargo_fips_registry::RegistryEntry;

/// Parsed components of a Rust target triple (`<arch>-<vendor>-<sys>[-<abi>]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetTriple {
    pub raw: String,
    pub arch: String,
    /// The OS/system family component (e.g. `linux`, `windows`, `darwin`).
    pub os_family: String,
}

impl TargetTriple {
    pub fn parse(triple: &str) -> Self {
        let parts: Vec<&str> = triple.split('-').collect();
        let arch = parts.first().copied().unwrap_or("").to_string();
        let os_family = match parts.len() {
            0 | 1 => String::new(),
            2 => parts[1].to_string(),
            _ => parts[2].to_string(),
        };
        Self {
            raw: triple.to_string(),
            arch,
            os_family,
        }
    }
}

/// Detect the host target triple via `rustc -vV` (the `host:` line).
pub fn host_triple() -> Option<String> {
    let output = Command::new("rustc").arg("-vV").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("host: ").map(|s| s.trim().to_string()))
}

/// Classification of a target environment against a certificate (spec §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OeClass {
    /// On the certificate's tested list.
    Tested,
    /// Same OS family as a tested OE, but not itself listed — defensible only by
    /// vendor affirmation.
    VendorAffirmable,
    /// Neither tested nor vendor-affirmable.
    OffCertificate,
}

/// Classify a target triple against a certificate's tested operating environments.
///
/// - exact triple match → [`OeClass::Tested`]
/// - same OS family as a tested OE → [`OeClass::VendorAffirmable`]
/// - otherwise → [`OeClass::OffCertificate`]
pub fn classify(triple: &str, entry: &RegistryEntry) -> OeClass {
    let target = TargetTriple::parse(triple);

    let tested_triples: Vec<&str> = entry
        .binding
        .tested_operating_environments
        .iter()
        .flat_map(|oe| oe.target_triples.iter().map(|s| s.as_str()))
        .collect();

    if tested_triples.iter().any(|tt| *tt == triple) {
        return OeClass::Tested;
    }

    let same_os_family = !target.os_family.is_empty()
        && tested_triples
            .iter()
            .any(|tt| TargetTriple::parse(tt).os_family == target.os_family);

    if same_os_family {
        OeClass::VendorAffirmable
    } else {
        OeClass::OffCertificate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cargo_fips_registry::Registry;

    fn cert_4816() -> RegistryEntry {
        Registry::builtin()
            .unwrap()
            .certificate("4816")
            .unwrap()
            .clone()
    }

    #[test]
    fn parses_triple_components() {
        let t = TargetTriple::parse("aarch64-unknown-linux-gnu");
        assert_eq!(t.arch, "aarch64");
        assert_eq!(t.os_family, "linux");
        assert_eq!(
            TargetTriple::parse("x86_64-pc-windows-msvc").os_family,
            "windows"
        );
        assert_eq!(
            TargetTriple::parse("aarch64-apple-darwin").os_family,
            "darwin"
        );
    }

    #[test]
    fn exact_match_is_tested() {
        assert_eq!(
            classify("x86_64-unknown-linux-gnu", &cert_4816()),
            OeClass::Tested
        );
    }

    #[test]
    fn aarch64_linux_is_tested() {
        // Graviton3 (aarch64) Linux is a tested OE on cert #4816 (SP Table 3).
        assert_eq!(
            classify("aarch64-unknown-linux-gnu", &cert_4816()),
            OeClass::Tested
        );
    }

    #[test]
    fn same_os_family_not_listed_is_vendor_affirmable() {
        // musl shares the linux OS family with the tested gnu triples, but is
        // not itself listed.
        assert_eq!(
            classify("x86_64-unknown-linux-musl", &cert_4816()),
            OeClass::VendorAffirmable
        );
    }

    #[test]
    fn other_os_is_off_certificate() {
        assert_eq!(
            classify("x86_64-pc-windows-msvc", &cert_4816()),
            OeClass::OffCertificate
        );
        assert_eq!(
            classify("aarch64-apple-darwin", &cert_4816()),
            OeClass::OffCertificate
        );
    }
}
