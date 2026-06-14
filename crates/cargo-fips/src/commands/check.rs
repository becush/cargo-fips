//! `cargo fips check` — the primary CI gate (spec §10.1).
//!
//! Resolves the dependency graph and verifies, against the declared `fips.toml`:
//! a validated backend is present; its FIPS mode is actually enabled; no
//! competing crypto crate is reachable; and the declared module/version is
//! validated by the claimed certificate. Fails closed.

use cargo_fips_registry::CertificateStatus;

use crate::backend::{self, FipsModeStatus};
use crate::cli::FipsCli;
use crate::config::FipsConfig;
use crate::exit::Exit;
use crate::metadata::{competing_crates, Graph};
use crate::report::{Report, NOT_A_DETERMINATION};

pub fn run(cli: &FipsCli) -> Exit {
    let manifest_dir = cli.manifest_dir();

    // --- Configuration (missing/invalid fips.toml is a usage error: exit 2) ---
    let (config, _config_path) = match FipsConfig::load(cli.config.as_deref(), &manifest_dir) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("error: could not load fips.toml ({err:#})");
            eprintln!("hint: `cargo fips check` requires a fips.toml; see the spec, §7.");
            return Exit::Usage;
        }
    };

    // --- Registry (data unavailable is exit 3) ---
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

    // --- Resolved dependency graph (cargo metadata failure is a usage error) ---
    let graph = match Graph::load(cli.manifest_path.as_deref(), None) {
        Ok(graph) => graph,
        Err(err) => {
            eprintln!("error: {err:#}");
            return Exit::Usage;
        }
    };

    if !cli.quiet {
        println!(
            "cargo fips check  —  certificate #{} ({}), {}",
            config.target.certificate,
            config.target.module,
            config.target.strictness.as_str()
        );
        println!();
    }

    let mut report = Report::new();

    // 1. A known validated backend must be present.
    let backends = backend::detect_backends(&graph);
    if backends.is_empty() {
        report.fail("no known validated crypto backend detected in the build graph");
    } else {
        let (be, detected) = &backends[0];
        report.pass(format!("validated backend detected: {}", detected.anchor_crate));

        // Policy: the backend must be allowed (when an allow-list is given).
        if !config.policy.allowed_backends.is_empty()
            && !config
                .policy
                .allowed_backends
                .iter()
                .any(|b| b == be.name())
        {
            report.fail(format!(
                "backend `{}` is not in allowed_backends {:?}",
                be.name(),
                config.policy.allowed_backends
            ));
        }

        // 2. FIPS mode must actually be enabled.
        match be.fips_enabled(&graph) {
            FipsModeStatus::Enabled => {
                report.pass(format!("{}: FIPS mode enabled", be.name()));
            }
            FipsModeStatus::Disabled => {
                report.fail(format!(
                    "{}: FIPS mode is NOT enabled (the `fips` feature / FIPS sys-crate is absent)",
                    be.name()
                ));
            }
            FipsModeStatus::Unknown => {
                report.warn(format!("{}: could not determine FIPS mode", be.name()));
            }
        }

        // 4. The declared module/version must line up with what's resolved.
        let identity = be.module_identity(&graph);
        if config.target.module != identity.module_id {
            report.warn(format!(
                "declared module `{}` differs from backend module `{}`",
                config.target.module, identity.module_id
            ));
        }
        if !identity
            .certificates
            .iter()
            .any(|c| c == &config.target.certificate)
        {
            report.fail(format!(
                "backend maps to certificate(s) {:?}, not the declared #{}",
                identity.certificates, config.target.certificate
            ));
        }
        if entry.validates_version(&config.target.version) {
            report.pass(format!(
                "module version {} is validated under certificate #{}",
                config.target.version, config.target.certificate
            ));
        } else {
            report.fail(format!(
                "declared version {} is not in certificate #{}'s validated set {:?}",
                config.target.version, config.target.certificate, entry.certificate.validated_versions
            ));
        }
        if let Some((module_crate, version)) = &identity.module_crate {
            report.info(format!("resolved module crate: {module_crate} {version}"));
        }
    }

    // Certificate lifecycle sanity.
    match entry.certificate.status {
        CertificateStatus::Active => {}
        CertificateStatus::Historical => report.warn(format!(
            "certificate #{} is HISTORICAL (superseded)",
            config.target.certificate
        )),
        CertificateStatus::Revoked => report.fail(format!(
            "certificate #{} is REVOKED",
            config.target.certificate
        )),
    }

    // 3. No competing, non-validated cryptographic crate may be reachable.
    if config.policy.forbid_competing_crypto {
        let mut allow = config.policy.allowed_backends.clone();
        // A backend's own crates are never "competing".
        allow.extend(
            ["aws-lc-rs", "aws-lc-sys", "aws-lc-fips-sys"]
                .iter()
                .map(|s| s.to_string()),
        );
        let competing = competing_crates(&graph, &allow);
        if competing.is_empty() {
            report.pass("no competing cryptographic crate reachable in build graph");
        } else {
            report.fail(format!(
                "competing cryptographic crate(s) reachable: {}",
                competing.join(", ")
            ));
        }
    }

    report.print(cli.quiet);

    let violations = report.violations();
    if !cli.quiet {
        println!();
        if violations == 0 {
            println!("  result: PASS (exit 0)");
        } else {
            println!(
                "  result: FAIL (exit 1) — {} policy violation{}",
                violations,
                if violations == 1 { "" } else { "s" }
            );
        }
        println!("  note: {NOT_A_DETERMINATION}");
    }

    if violations == 0 {
        Exit::Pass
    } else {
        Exit::PolicyViolation
    }
}
