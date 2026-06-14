//! `cargo fips attest` — evidence generation (spec §10.4, §11).
//!
//! STATUS: not yet implemented (Phase 3). When implemented, this emits a
//! CycloneDX 1.6 CBOM plus a human-readable summary suitable for an SP 800-53
//! SC-13 control narrative, optionally wrapped in in-toto/SLSA provenance and
//! signed with cosign.

use crate::cli::FipsCli;
use crate::exit::Exit;

pub fn run(_cli: &FipsCli) -> Exit {
    eprintln!("cargo fips attest: not yet implemented (Phase 3).");
    eprintln!("would emit a CycloneDX 1.6 CBOM and a human-readable compliance summary.");
    Exit::Usage
}
