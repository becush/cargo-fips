//! `cargo fips oe` — operating-environment classification (spec §10.2).
//!
//! Resolves the target triple(s) to evaluate and classifies each against the
//! claimed certificate's tested operating environments:
//!
//! - **tested** — on the certificate → pass;
//! - **vendor-affirmable** — same OS family as a tested OE, but not listed →
//!   pass under `strictness = allow-vendor-affirmed` (with a caveat), otherwise a
//!   violation;
//! - **off-certificate** — neither → a violation under
//!   `deny_off_certificate_oe`, otherwise a warning.
//!
//! Which triples are evaluated:
//! - `--target T` → just `T`;
//! - else the declared `[target] allowed_oes` (the project's support matrix);
//! - else the host triple.
//!
//! This command does not run `cargo metadata`; it needs only `fips.toml`, the
//! registry, and (for host detection) `rustc`.

use cargo_fips_registry::CertificateStatus;

use crate::cli::{FipsCli, OeArgs};
use crate::config::{FipsConfig, Strictness};
use crate::environment::{classify, host_triple, OeClass};
use crate::exit::Exit;
use crate::report::{Report, NOT_A_DETERMINATION};

pub fn run(cli: &FipsCli, args: &OeArgs) -> Exit {
    let manifest_dir = cli.manifest_dir();

    let (config, _config_path) = match FipsConfig::load(cli.config.as_deref(), &manifest_dir) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("error: could not load fips.toml ({err:#})");
            eprintln!("hint: `cargo fips oe` requires a fips.toml; see the spec, §7.");
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

    // Decide which triples to evaluate, and remember where the list came from.
    let host = host_triple();
    let (targets, source): (Vec<String>, &str) = if let Some(target) = &args.target {
        (vec![target.clone()], "--target")
    } else if !config.target.allowed_oes.is_empty() {
        (config.target.allowed_oes.clone(), "declared allowed_oes")
    } else if let Some(h) = &host {
        (vec![h.clone()], "host")
    } else {
        eprintln!(
            "error: no --target given, no allowed_oes declared, and the host triple could not be \
             detected (is rustc on PATH?)"
        );
        return Exit::Usage;
    };

    if !cli.quiet {
        println!(
            "cargo fips oe  —  certificate #{} ({}), {}",
            config.target.certificate,
            config.target.module,
            config.target.strictness.as_str()
        );
        if let Some(h) = &host {
            println!("  host target: {h}");
        }
        println!("  evaluating: {source}");
        println!();
    }

    let mut report = Report::new();

    for triple in &targets {
        match classify(triple, entry) {
            OeClass::Tested => report.pass(format!(
                "{triple}: tested — on certificate #{}",
                config.target.certificate
            )),
            OeClass::VendorAffirmable => match config.target.strictness {
                Strictness::AllowVendorAffirmed => report.warn(format!(
                    "{triple}: vendor-affirmable — not on certificate #{}'s tested list; \
                     defensible only by vendor affirmation",
                    config.target.certificate
                )),
                Strictness::TestedOnly => report.fail(format!(
                    "{triple}: vendor-affirmable — not on certificate #{}'s tested list \
                     (strictness = tested-only)",
                    config.target.certificate
                )),
            },
            OeClass::OffCertificate => {
                if config.policy.deny_off_certificate_oe {
                    report.fail(format!(
                        "{triple}: off-certificate — not defensible (deny_off_certificate_oe = true)"
                    ))
                } else {
                    report.warn(format!(
                        "{triple}: off-certificate — not on certificate #{} and not vendor-affirmable",
                        config.target.certificate
                    ))
                }
            }
        }
    }

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
