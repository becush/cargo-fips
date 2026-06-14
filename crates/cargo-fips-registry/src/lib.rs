//! Typed FIPS module registry for `cargo-fips`.
//!
//! The registry is the curated, machine-readable form of facts otherwise
//! scattered across CMVP Security Policy PDFs: which certificate covers which
//! module versions, which operating environments were tested, and which
//! algorithms are approved. See the project spec, §8.
//!
//! ```no_run
//! use cargo_fips_registry::Registry;
//!
//! let registry = Registry::builtin()?;
//! if let Some(entry) = registry.certificate("4816") {
//!     println!("{} — status {:?}", entry.module.id, entry.certificate.status);
//! }
//! # Ok::<(), cargo_fips_registry::RegistryError>(())
//! ```

pub mod loader;
pub mod model;

pub use loader::{Registry, RegistryError};
pub use model::{
    ApprovedAlgorithm, Certificate, CertificateBinding, CertificateStatus, Module, ModuleType,
    OperatingEnvironment, RegistryEntry,
};
