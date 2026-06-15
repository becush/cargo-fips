//! Resolving effective build settings and the guard rule set (spec §10.3).
//!
//! `guard` is defense-in-depth, never a guarantee. For a **source-built** module
//! the in-core integrity hash shifts when the compiler, flags, or memory layout
//! change, so hash-perturbing settings are hard failures. For a **prebuilt
//! static** module the validated artifact is not recompiled by Rust flags, so
//! the same settings are warnings (they affect crypto-adjacent code, or could
//! attempt to relink the artifact) rather than failures. The recomputed in-core
//! hash remains ground truth.
//!
//! Resolution here is a first cut: `RUSTFLAGS` / `CARGO_ENCODED_RUSTFLAGS` from
//! the environment, else `[build] rustflags` from `.cargo/config.toml`; and the
//! `[profile.<profile>]` table from the manifest. It does not yet merge every
//! Cargo config layer.

use std::path::Path;

use crate::backend::BoundaryKind;
use crate::report::Report;

/// The build settings relevant to boundary integrity.
#[derive(Debug, Clone, Default)]
pub struct BuildSettings {
    pub profile: String,
    pub rustflags: Vec<String>,
    pub rustflags_source: String,
    pub lto: Option<String>,
    pub codegen_units: Option<i64>,
    pub opt_level: Option<String>,
    pub panic: Option<String>,
    pub strip: Option<String>,
}

impl BuildSettings {
    /// Resolve settings for `profile` from the environment, `.cargo/config.toml`,
    /// and the manifest at `manifest_dir`.
    pub fn resolve(manifest_dir: &Path, profile: &str) -> Self {
        let (rustflags, rustflags_source) = rustflags_from_env()
            .or_else(|| rustflags_from_config(manifest_dir))
            .unwrap_or_else(|| (Vec::new(), "none".to_string()));

        let mut settings = Self {
            profile: profile.to_string(),
            rustflags,
            rustflags_source,
            ..Self::default()
        };

        let manifest = manifest_dir.join("Cargo.toml");
        if let Ok(raw) = std::fs::read_to_string(&manifest) {
            if let Ok(value) = toml::from_str::<toml::Value>(&raw) {
                if let Some(p) = value.get("profile").and_then(|p| p.get(profile)) {
                    settings.lto = p.get("lto").map(scalar_to_string);
                    settings.codegen_units = p.get("codegen-units").and_then(|v| v.as_integer());
                    settings.opt_level = p.get("opt-level").map(scalar_to_string);
                    settings.panic = p.get("panic").and_then(|v| v.as_str().map(str::to_string));
                    settings.strip = p.get("strip").map(scalar_to_string);
                }
            }
        }
        settings
    }
}

fn rustflags_from_env() -> Option<(Vec<String>, String)> {
    if let Ok(encoded) = std::env::var("CARGO_ENCODED_RUSTFLAGS") {
        if !encoded.is_empty() {
            let flags = encoded.split('\u{1f}').map(str::to_string).collect();
            return Some((flags, "CARGO_ENCODED_RUSTFLAGS".to_string()));
        }
    }
    if let Ok(raw) = std::env::var("RUSTFLAGS") {
        if !raw.trim().is_empty() {
            let flags = raw.split_whitespace().map(str::to_string).collect();
            return Some((flags, "RUSTFLAGS".to_string()));
        }
    }
    None
}

fn rustflags_from_config(manifest_dir: &Path) -> Option<(Vec<String>, String)> {
    for name in [".cargo/config.toml", ".cargo/config"] {
        let path = manifest_dir.join(name);
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = toml::from_str::<toml::Value>(&raw) else {
            continue;
        };
        if let Some(flags) = value
            .get("build")
            .and_then(|b| b.get("rustflags"))
            .and_then(toml_rustflags_to_vec)
        {
            return Some((flags, path.display().to_string()));
        }
    }
    None
}

fn toml_rustflags_to_vec(value: &toml::Value) -> Option<Vec<String>> {
    match value {
        toml::Value::String(s) => Some(s.split_whitespace().map(str::to_string).collect()),
        toml::Value::Array(arr) => Some(
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
        ),
        _ => None,
    }
}

fn scalar_to_string(value: &toml::Value) -> String {
    match value {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Float(f) => f.to_string(),
        other => other.to_string(),
    }
}

/// First rustflag token containing `needle` (handles `-C target-cpu=…` split
/// across tokens as well as `-Ctarget-cpu=…`).
fn find_flag<'a>(flags: &'a [String], needle: &str) -> Option<&'a str> {
    flags
        .iter()
        .map(String::as_str)
        .find(|token| token.contains(needle))
}

fn is_truthy_lto(value: &str) -> bool {
    matches!(value.to_ascii_lowercase().as_str(), "true" | "fat" | "thin")
}

fn is_truthy_strip(value: &str) -> bool {
    matches!(value.to_ascii_lowercase().as_str(), "true" | "symbols")
}

/// Evaluate build settings against a boundary kind, producing findings.
///
/// Pure (no I/O): all inputs are in `settings` and `boundary`.
pub fn evaluate(settings: &BuildSettings, boundary: BoundaryKind) -> Report {
    let mut report = Report::new();

    // For platform-provided / out-of-process modules, Rust build flags do not
    // touch the validated module at all.
    match boundary {
        BoundaryKind::PlatformProvided => {
            report.info(
                "boundary is platform-provided; Rust build flags do not alter the validated module",
            );
            return report;
        }
        BoundaryKind::OutOfProcess => {
            report.info(
                "boundary is out-of-process; Rust build flags do not alter the validated module",
            );
            return report;
        }
        _ => {}
    }

    let source_built = matches!(boundary, BoundaryKind::SourceBuilt);
    let mut flagged = false;

    for needle in ["target-cpu", "target-feature"] {
        if let Some(token) = find_flag(&settings.rustflags, needle) {
            flagged = true;
            if source_built {
                report.fail(format!(
                    "RUSTFLAGS sets {token} — changes generated code and shifts the in-core integrity hash"
                ));
            } else {
                report.warn(format!(
                    "RUSTFLAGS sets {token} — does not recompile the prebuilt module, but affects crypto-adjacent code"
                ));
            }
        }
    }

    let lto_source = find_flag(&settings.rustflags, "lto")
        .map(|t| format!("RUSTFLAGS {t}"))
        .or_else(|| {
            settings
                .lto
                .as_ref()
                .filter(|v| is_truthy_lto(v))
                .map(|v| format!("profile lto = {v}"))
        });
    if let Some(src) = lto_source {
        flagged = true;
        if source_built {
            report.fail(format!(
                "{src} — LTO reorganizes code across the boundary and shifts the in-core integrity hash"
            ));
        } else {
            report.warn(format!(
                "{src} — LTO can attempt to alter or relink the prebuilt validated artifact"
            ));
        }
    }

    if settings.panic.as_deref() == Some("abort") {
        flagged = true;
        report.warn("profile panic = \"abort\" — changes code generation around the boundary");
    }

    if source_built {
        if let Some(cu) = settings.codegen_units {
            flagged = true;
            report.warn(format!(
                "profile codegen-units = {cu} — may change code layout and shift the in-core integrity hash"
            ));
        }
        if let Some(ol) = &settings.opt_level {
            flagged = true;
            report.warn(format!(
                "profile opt-level = {ol} is set — a non-validated optimization level may shift the in-core integrity hash"
            ));
        }
    }

    if let Some(strip) = &settings.strip {
        if is_truthy_strip(strip) {
            flagged = true;
            report.warn(format!(
                "profile strip = {strip} — stripping symbols can interfere with the module's integrity self-check"
            ));
        }
    }

    if !flagged {
        report.pass("no boundary-perturbing build settings detected");
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings_with_rustflags(flags: &[&str]) -> BuildSettings {
        BuildSettings {
            profile: "release".to_string(),
            rustflags: flags.iter().map(|s| s.to_string()).collect(),
            rustflags_source: "test".to_string(),
            ..BuildSettings::default()
        }
    }

    #[test]
    fn clean_settings_pass() {
        let s = settings_with_rustflags(&[]);
        let r = evaluate(&s, BoundaryKind::PrebuiltStatic);
        assert_eq!(r.violations(), 0);
        assert!(r
            .findings()
            .iter()
            .any(|f| f.message.contains("no boundary-perturbing")));
    }

    #[test]
    fn target_cpu_fails_for_source_built() {
        let s = settings_with_rustflags(&["-C", "target-cpu=native"]);
        let r = evaluate(&s, BoundaryKind::SourceBuilt);
        assert_eq!(
            r.violations(),
            1,
            "source-built should hard-fail on target-cpu"
        );
    }

    #[test]
    fn target_cpu_only_warns_for_prebuilt_static() {
        let s = settings_with_rustflags(&["-Ctarget-cpu=native"]);
        let r = evaluate(&s, BoundaryKind::PrebuiltStatic);
        assert_eq!(r.violations(), 0, "prebuilt-static should warn, not fail");
        assert!(r
            .findings()
            .iter()
            .any(|f| f.message.contains("target-cpu")));
    }

    #[test]
    fn lto_profile_fails_for_source_built() {
        let mut s = settings_with_rustflags(&[]);
        s.lto = Some("fat".to_string());
        let r = evaluate(&s, BoundaryKind::SourceBuilt);
        assert_eq!(r.violations(), 1);
    }

    #[test]
    fn lto_off_is_not_flagged() {
        let mut s = settings_with_rustflags(&[]);
        s.lto = Some("off".to_string());
        let r = evaluate(&s, BoundaryKind::SourceBuilt);
        assert_eq!(r.violations(), 0);
    }

    #[test]
    fn platform_provided_ignores_flags() {
        let s = settings_with_rustflags(&["-C", "target-cpu=native"]);
        let r = evaluate(&s, BoundaryKind::PlatformProvided);
        assert_eq!(r.violations(), 0);
        assert!(r
            .findings()
            .iter()
            .any(|f| f.message.contains("platform-provided")));
    }

    #[test]
    fn out_of_process_ignores_flags() {
        let s = settings_with_rustflags(&["-C", "target-cpu=native"]);
        let r = evaluate(&s, BoundaryKind::OutOfProcess);
        assert_eq!(r.violations(), 0);
        assert!(r
            .findings()
            .iter()
            .any(|f| f.message.contains("out-of-process")));
    }
}
