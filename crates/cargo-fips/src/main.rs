//! `cargo-fips` — a Cargo subcommand for FIPS 140-3 build assurance and evidence
//! generation in Rust. See the project spec for the full design.
//!
//! Evidence, not absolution: a green `check` means "no detected drift from the
//! declared, validated configuration," not "validated."

mod backend;
mod build_settings;
mod cli;
mod commands;
mod config;
mod environment;
mod exit;
mod metadata;
mod report;

use std::process::ExitCode;

use clap::Parser;

use cli::{CargoCli, Command};

fn main() -> ExitCode {
    let cli = match CargoCli::parse() {
        CargoCli::Fips(cli) => cli,
    };

    let exit = match &cli.command {
        Command::Check => commands::check::run(&cli),
        Command::Oe(args) => commands::oe::run(&cli, args),
        Command::Guard(args) => commands::guard::run(&cli, args),
        Command::Attest => commands::attest::run(&cli),
    };

    ExitCode::from(exit.code())
}
