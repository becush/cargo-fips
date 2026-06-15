//! `cargo-fips` — a Cargo subcommand for FIPS 140-3 build assurance and evidence
//! generation in Rust. See the project spec for the full design.
//!
//! Evidence, not absolution: a green `check` means "no detected drift from the
//! declared, validated configuration," not "validated."

mod backend;
mod build_settings;
mod cbom;
mod cli;
mod commands;
mod config;
mod environment;
mod exit;
mod metadata;
mod report;
mod signing;

use std::process::ExitCode;

use clap::Parser;

use cli::{CargoCli, Command};

fn main() -> ExitCode {
    let CargoCli::Fips(cli) = CargoCli::parse();

    let exit = match &cli.command {
        Command::Init(args) => commands::init::run(&cli, args),
        Command::Check => commands::check::run(&cli),
        Command::Oe(args) => commands::oe::run(&cli, args),
        Command::Guard(args) => commands::guard::run(&cli, args),
        Command::Attest(args) => commands::attest::run(&cli, args),
    };

    ExitCode::from(exit.code())
}
