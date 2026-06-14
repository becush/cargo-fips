//! `cargo fips guard` — build-flag guard (spec §10.3).
//!
//! Determines the validated module's boundary kind from the declared backend,
//! resolves the effective build settings, and flags those known to perturb the
//! boundary. Severity is per-backend (source-built fails on hash-shifting
//! settings; prebuilt-static warns). Defense-in-depth, never a guarantee.
//!
//! Offline: needs only `fips.toml`, the manifest, and the environment — no
//! `cargo metadata`.

use crate::backend::{all_backends, BoundaryKind};
use crate::build_settings::{evaluate, BuildSettings};
use crate::cli::{FipsCli, GuardArgs};
use crate::config::FipsConfig;
use crate::exit::Exit;
use crate::report::NOT_A_DETERMINATION;

pub fn run(cli: &FipsCli, args: &GuardArgs) -> Exit {
    let manifest_dir = cli.manifest_dir();

    let (config, _config_path) = match FipsConfig::load(cli.config.as_deref(), &manifest_dir) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("error: could not load fips.toml ({err:#})");
            eprintln!("hint: `cargo fips guard` requires a fips.toml; see the spec, §7.");
            return Exit::Usage;
        }
    };

    let profile = args
        .profile
        .clone()
        .unwrap_or_else(|| "release".to_string());

    // Boundary kind comes from the declared backend; default conservatively to
    // source-built (the stricter rule set) when it can't be determined.
    let declared_backend = config.policy.allowed_backends.first().cloned();
    let (boundary, boundary_note) = match declared_backend.as_deref() {
        Some(name) => match all_backends().into_iter().find(|b| b.name() == name) {
            Some(backend) => (
                backend.build_parameters().boundary,
                format!("backend {name}"),
            ),
            None => (
                BoundaryKind::SourceBuilt,
                format!("unknown backend `{name}` — assuming source-built (conservative)"),
            ),
        },
        None => (
            BoundaryKind::SourceBuilt,
            "no allowed_backends declared — assuming source-built (conservative)".to_string(),
        ),
    };

    let settings = BuildSettings::resolve(&manifest_dir, &profile);

    if !cli.quiet {
        println!(
            "cargo fips guard  —  {} build, boundary: {}",
            settings.profile,
            boundary.as_str()
        );
        println!("  {boundary_note}");
        println!("  rustflags source: {}", settings.rustflags_source);
        if !settings.rustflags.is_empty() {
            println!("  rustflags: {}", settings.rustflags.join(" "));
        }
        println!();
    }

    let report = evaluate(&settings, boundary);
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
        println!(
            "  note: guard is defense-in-depth; for source-built modules the recomputed in-core \
             integrity hash remains ground truth."
        );
        println!("  note: {NOT_A_DETERMINATION}");
    }

    if violations == 0 {
        Exit::Pass
    } else {
        Exit::PolicyViolation
    }
}
