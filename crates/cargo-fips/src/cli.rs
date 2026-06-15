//! Command-line surface.
//!
//! `cargo-fips` is a Cargo subcommand, so it is invoked as `cargo fips <CMD>`.
//! Cargo runs the `cargo-fips` binary with `fips` as the first argument, which
//! the [`CargoCli`] enum absorbs.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Top-level wrapper so the binary parses cleanly both as `cargo fips ...`
/// and when run directly as `cargo-fips fips ...`.
#[derive(Debug, Parser)]
#[command(name = "cargo-fips", bin_name = "cargo")]
pub enum CargoCli {
    /// FIPS 140-3 build assurance and evidence for Rust projects.
    #[command(name = "fips", version, about)]
    Fips(FipsCli),
}

/// The `fips` subcommand and its global options.
#[derive(Debug, Args)]
pub struct FipsCli {
    #[command(subcommand)]
    pub command: Command,

    /// Path to `fips.toml` (defaults to `<manifest dir>/fips.toml`).
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Path to the crate/workspace `Cargo.toml` to analyze.
    #[arg(long, global = true, value_name = "FILE")]
    pub manifest_path: Option<PathBuf>,

    /// Machine-friendly output (one finding per line, no decoration).
    #[arg(long, global = true)]
    pub quiet: bool,
}

impl FipsCli {
    /// Directory used to resolve a relative `fips.toml` / registry path.
    pub fn manifest_dir(&self) -> PathBuf {
        match &self.manifest_path {
            Some(mp) => mp
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from(".")),
            None => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scaffold a fips.toml by detecting the backend in the dependency graph.
    Init(InitArgs),

    /// Verify the resolved build against the declared FIPS posture (primary CI gate).
    Check,

    /// Classify the target operating environment against the certificate.
    Oe(OeArgs),

    /// Detect build flags that may perturb the validated boundary.
    Guard(GuardArgs),

    /// Emit a CycloneDX CBOM attestation plus a human-readable summary.
    Attest(AttestArgs),
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Output path (defaults to `<manifest dir>/fips.toml`).
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Overwrite an existing fips.toml.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct OeArgs {
    /// Target triple to classify (defaults to the host target).
    #[arg(long, value_name = "TRIPLE")]
    pub target: Option<String>,
}

#[derive(Debug, Args)]
pub struct GuardArgs {
    /// Cargo profile to inspect (default: release).
    #[arg(long, value_name = "PROFILE")]
    pub profile: Option<String>,
}

#[derive(Debug, Args)]
pub struct AttestArgs {
    /// Target triple to attest (defaults to the host target).
    #[arg(long, value_name = "TRIPLE")]
    pub target: Option<String>,

    /// Output path for the CBOM (overrides `[attest] output` in fips.toml).
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Sign the CBOM with cosign (overrides `[attest] sign`).
    #[arg(long)]
    pub sign: bool,

    /// cosign private key for key-based signing (otherwise keyless).
    #[arg(long, value_name = "FILE")]
    pub cosign_key: Option<PathBuf>,
}
