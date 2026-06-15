//! `cargo fips attest` — evidence generation (spec §10.4, §11).
//!
//! Resolves module identity, the operating environment actually used, the
//! approved-algorithm set, and build provenance, then emits a CycloneDX 1.6 CBOM
//! to the configured output and prints a human-readable SP 800-53 SC-13 control
//! narrative. When requested, the CBOM is signed via cosign (see `crate::signing`).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use cargo_fips_registry::{ApprovedAlgorithm, CertificateStatus, OperatingEnvironment};

use crate::backend;
use crate::cbom::{build_cbom, AlgorithmEntry, AttestationInput};
use crate::cli::{AttestArgs, FipsCli};
use crate::config::FipsConfig;
use crate::environment::{classify, host_triple, OeClass};
use crate::exit::Exit;
use crate::metadata::Graph;
use crate::report::NOT_A_DETERMINATION;

pub fn run(cli: &FipsCli, args: &AttestArgs) -> Exit {
    let manifest_dir = cli.manifest_dir();

    let (config, _config_path) = match FipsConfig::load(cli.config.as_deref(), &manifest_dir) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("error: could not load fips.toml ({err:#})");
            eprintln!("hint: `cargo fips attest` requires a fips.toml; see the spec, §7.");
            return Exit::Usage;
        }
    };

    let registry = match config.load_registry(&manifest_dir) {
        Ok(registry) => registry,
        Err(err) => {
            eprintln!("error: {err:#}");
            return Exit::RegistryUnavailable;
        }
    };
    let entry = match registry.certificate(&config.target.certificate) {
        Some(entry) => entry,
        None => {
            eprintln!(
                "error: registry has no data for certificate #{}",
                config.target.certificate
            );
            return Exit::RegistryUnavailable;
        }
    };

    let graph = match Graph::load(cli.manifest_path.as_deref(), None) {
        Ok(graph) => graph,
        Err(err) => {
            eprintln!("error: {err:#}");
            return Exit::Usage;
        }
    };

    let backends = backend::detect_backends(&graph);
    let identity = match backends.first() {
        Some((be, _)) => be.module_identity(&graph),
        None => {
            eprintln!("error: no validated backend detected in the build graph; nothing to attest");
            return Exit::Usage;
        }
    };

    // Operating environment actually targeted.
    let host = host_triple();
    let target_triple = args
        .target
        .clone()
        .or(host)
        .unwrap_or_else(|| "unknown".to_string());
    let classification = if target_triple == "unknown" {
        OeClass::OffCertificate
    } else {
        classify(&target_triple, entry)
    };
    let oe_description = entry.tested_oe_for_triple(&target_triple).map(describe_oe);

    let algorithms: Vec<AlgorithmEntry> = entry
        .binding
        .approved_algorithms
        .iter()
        .map(|a| AlgorithmEntry {
            name: a.name.clone(),
            modes: a.modes.clone(),
            parameter_set: derive_parameter_set(a),
            cavp_certificate: a.cavp_certificate.clone(),
            oid: a.oid.clone(),
        })
        .collect();

    // Provenance.
    let mut provenance: Vec<(String, String)> = vec![
        (
            "fips:tool".into(),
            format!("cargo-fips {}", env!("CARGO_PKG_VERSION")),
        ),
        ("build:target".into(), target_triple.clone()),
        ("fips:registrySource".into(), config.registry.source.clone()),
    ];
    if config.attest.provenance {
        if let Some(version) = rustc_version() {
            provenance.push(("build:rustc".into(), version));
        }
        if let Some(sha) = git_commit(&manifest_dir) {
            provenance.push(("build:gitCommit".into(), sha));
        }
    }

    let (project_name, project_version) = match graph.root_package() {
        Some((name, version)) => (Some(name), Some(version)),
        None => (None, None),
    };

    let input = AttestationInput {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        project_name,
        project_version,
        module_id: entry.module.id.clone(),
        vendor: entry.module.vendor.clone(),
        declared_version: config.target.version.clone(),
        resolved_crate: identity.module_crate.clone(),
        cmvp_number: entry.certificate.cmvp_number.clone(),
        cmvp_status: status_str(entry.certificate.status).to_string(),
        security_level: entry.module.security_level,
        integrity_technique: entry.module.integrity_technique.clone(),
        target_triple: target_triple.clone(),
        oe_classification: classification.as_str().to_string(),
        oe_description: oe_description.clone(),
        algorithms,
        provenance,
        strictness: config.target.strictness.as_str().to_string(),
    };

    let cbom = build_cbom(&input, now_secs());

    // Write the CBOM.
    let output_path = resolve_output(args, &config, &manifest_dir);
    if let Some(parent) = output_path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            eprintln!("error: creating {}: {err}", parent.display());
            return Exit::Usage;
        }
    }
    let json = serde_json::to_string_pretty(&cbom).unwrap_or_else(|_| cbom.to_string());
    if let Err(err) = std::fs::write(&output_path, format!("{json}\n")) {
        eprintln!("error: writing {}: {err}", output_path.display());
        return Exit::Usage;
    }

    // Optional cosign signing (spec §10.4). Delegated to the cosign binary.
    let signing_note = if config.attest.sign || args.sign {
        let key = args
            .cosign_key
            .as_deref()
            .or(config.attest.cosign_key.as_deref());
        match crate::signing::cosign_sign(&output_path, key) {
            Ok(outputs) => Some(format!("signed (cosign): {}", outputs.describe())),
            Err(err) => {
                eprintln!("error: signing failed: {err}");
                eprintln!("wrote unsigned CBOM at {}", output_path.display());
                return Exit::Usage;
            }
        }
    } else {
        None
    };

    if cli.quiet {
        println!("{}", output_path.display());
        return Exit::Pass;
    }

    let alg_names: Vec<&str> = input.algorithms.iter().map(|a| a.name.as_str()).collect();

    println!(
        "cargo fips attest  —  certificate #{} ({})",
        input.cmvp_number, input.module_id
    );
    println!();
    println!(
        "  module:      {} {} (vendor: {})",
        input.module_id, input.declared_version, input.vendor
    );
    if let Some((crate_name, crate_ver)) = &input.resolved_crate {
        println!("  resolved:    {crate_name} {crate_ver}");
    }
    println!(
        "  certificate: #{} — FIPS 140-3 Level {} ({})",
        input.cmvp_number, input.security_level, input.cmvp_status
    );
    println!("  integrity:   {}", input.integrity_technique);
    println!(
        "  environment: {} [{}]",
        input.target_triple, input.oe_classification
    );
    if let Some(desc) = &input.oe_description {
        println!("               {desc}");
    }
    println!("  algorithms:  {}", alg_names.join(", "));
    println!();
    println!("  SP 800-53 SC-13 (Cryptographic Protection) — draft narrative:");
    println!(
        "  \"Cryptographic services are provided by {} {} operating in its",
        input.module_id, input.declared_version
    );
    println!(
        "   FIPS-approved mode, validated under NIST CMVP certificate #{} (FIPS 140-3,",
        input.cmvp_number
    );
    println!(
        "   Level {}). Module integrity is verified at load via {}. The deployment",
        input.security_level, input.integrity_technique
    );
    println!(
        "   target {} is {} for this certificate. Approved algorithms",
        input.target_triple, input.oe_classification
    );
    println!("   include {}.\"", alg_names.join(", "));
    println!();
    println!(
        "  wrote {} ({})",
        output_path.display(),
        config.attest.format
    );
    if let Some(note) = &signing_note {
        println!("  {note}");
    }
    println!("  note: {NOT_A_DETERMINATION}");

    Exit::Pass
}

fn resolve_output(args: &AttestArgs, config: &FipsConfig, manifest_dir: &Path) -> PathBuf {
    let path = args
        .output
        .clone()
        .unwrap_or_else(|| config.attest.output.clone());
    if path.is_absolute() {
        path
    } else {
        manifest_dir.join(path)
    }
}

fn describe_oe(oe: &OperatingEnvironment) -> String {
    let mut s = oe.os.clone();
    if let Some(version) = &oe.os_version {
        s.push(' ');
        s.push_str(version);
    }
    s.push_str(" (");
    s.push_str(&oe.arch);
    if let Some(processor) = &oe.processor {
        s.push_str(", ");
        s.push_str(processor);
    }
    s.push(')');
    s
}

/// Derive a descriptor string from an algorithm's parameters.
fn derive_parameter_set(alg: &ApprovedAlgorithm) -> Option<String> {
    if let Some(sizes) = alg.parameters.get("key_sizes").and_then(|v| v.as_array()) {
        let joined: Vec<String> = sizes
            .iter()
            .filter_map(|v| v.as_i64().map(|n| n.to_string()))
            .collect();
        if !joined.is_empty() {
            return Some(joined.join("/"));
        }
    }
    if let Some(curves) = alg.parameters.get("curves").and_then(|v| v.as_array()) {
        let joined: Vec<String> = curves
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        if !joined.is_empty() {
            return Some(joined.join(", "));
        }
    }
    if alg.name.to_ascii_uppercase().starts_with("SHA") && !alg.modes.is_empty() {
        return Some(alg.modes.join("/"));
    }
    None
}

fn status_str(status: CertificateStatus) -> &'static str {
    match status {
        CertificateStatus::Active => "active",
        CertificateStatus::Historical => "historical",
        CertificateStatus::Revoked => "revoked",
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn rustc_version() -> Option<String> {
    let output = Command::new("rustc").arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    Some(text.trim().to_string())
}

fn git_commit(manifest_dir: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(manifest_dir)
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let sha = text.trim();
    if sha.is_empty() {
        None
    } else {
        Some(sha.to_string())
    }
}
