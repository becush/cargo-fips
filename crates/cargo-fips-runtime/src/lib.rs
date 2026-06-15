//! Runtime companion for `cargo-fips` (spec §10.5).
//!
//! `cargo fips check` proves a build *was configured* for FIPS. But FIPS is also
//! a *runtime* property: the loaded module must report FIPS mode active and its
//! power-on self-test (POST) must have passed. This crate is the small library
//! a downstream application links to assert that at startup and to record module
//! identity and service-indicator status.
//!
//! It is the meeting point with a future unified provider trait, where an
//! `is_fips()` hook becomes the [`FipsProbe`] implementation.
//!
//! # Probes
//!
//! - [`NullProbe`] (always available) reports [`FipsState::Unknown`] — the
//!   dependency-free default.
//! - [`AwsLcRsProbe`] (behind the `aws-lc-rs` feature) calls
//!   `aws_lc_rs::try_fips_mode()` to report the live state of the linked AWS-LC
//!   module (CMVP certificate #4816).
//!
//! Other backends implement [`FipsProbe`] the same way; this trait is the hook a
//! future unified provider abstraction (`is_fips()`) would satisfy.
//!
//! # Example
//!
//! ```
//! use cargo_fips_runtime::{assert_fips, FipsState, NullProbe, OnFailure};
//!
//! // With a real probe this would panic if the module is not in FIPS mode.
//! let state = assert_fips!(NullProbe, OnFailure::Warn);
//! assert_eq!(state, FipsState::Unknown);
//! ```
//!
//! With the `aws-lc-rs` feature, assert at startup against the real module:
//!
//! ```ignore
//! use cargo_fips_runtime::{assert_fips, AwsLcRsProbe, OnFailure};
//!
//! // Panics unless the linked AWS-LC is in FIPS-approved mode.
//! assert_fips!(AwsLcRsProbe, OnFailure::Panic);
//! ```

#![forbid(unsafe_code)]

use std::fmt;

/// Result of a runtime FIPS check.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FipsState {
    /// The module reports FIPS mode active and POST passed.
    Enabled,
    /// The module is loaded but not operating in FIPS mode.
    Disabled,
    /// Could not be determined (e.g. no probe wired up).
    #[default]
    Unknown,
}

impl fmt::Display for FipsState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            FipsState::Enabled => "enabled",
            FipsState::Disabled => "disabled",
            FipsState::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

/// Identity of the cryptographic module observed at runtime.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleReport {
    /// Registry module id, if known (e.g. `aws-lc-fips`).
    pub module: Option<String>,
    /// Module version string, if the backend exposes it.
    pub version: Option<String>,
    /// CMVP certificate number the module maps to, if known.
    pub certificate: Option<String>,
    /// Observed FIPS state.
    pub state: FipsState,
}

/// A backend-specific hook that reports live FIPS status and module identity.
///
/// Implementors wrap whatever the validated backend exposes at runtime.
pub trait FipsProbe {
    /// The live FIPS state of the loaded module.
    fn state(&self) -> FipsState;

    /// Module identity, for logging into an audit trail.
    fn identity(&self) -> ModuleReport {
        ModuleReport {
            state: self.state(),
            ..ModuleReport::default()
        }
    }
}

/// A no-op probe that always reports [`FipsState::Unknown`].
///
/// Used as the default until a backend probe is wired in.
pub struct NullProbe;

impl FipsProbe for NullProbe {
    fn state(&self) -> FipsState {
        FipsState::Unknown
    }
}

/// A [`FipsProbe`] backed by `aws-lc-rs` (AWS-LC, CMVP certificate #4816).
///
/// Available behind the `aws-lc-rs` crate feature. It calls
/// `aws_lc_rs::try_fips_mode()`, which returns `Ok` only when the linked AWS-LC
/// is the FIPS module operating in approved mode; any error maps to
/// [`FipsState::Disabled`]. The power-on self-test (POST) runs inside the module
/// at load, so reaching this call already implies POST did not abort.
#[cfg(feature = "aws-lc-rs")]
pub struct AwsLcRsProbe;

#[cfg(feature = "aws-lc-rs")]
impl FipsProbe for AwsLcRsProbe {
    fn state(&self) -> FipsState {
        match aws_lc_rs::try_fips_mode() {
            Ok(()) => FipsState::Enabled,
            Err(_) => FipsState::Disabled,
        }
    }

    fn identity(&self) -> ModuleReport {
        ModuleReport {
            module: Some("aws-lc-fips".to_string()),
            version: None,
            certificate: Some("4816".to_string()),
            state: self.state(),
        }
    }
}

/// What to do when the runtime assertion is not satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnFailure {
    /// Panic (abort startup). Appropriate for fail-closed deployments.
    Panic,
    /// Log a warning to stderr and continue.
    Warn,
}

/// Assert FIPS mode using `probe`, reacting per `on_failure`.
///
/// - [`FipsState::Enabled`] → returns immediately.
/// - [`FipsState::Disabled`] → panics or warns per `on_failure`.
/// - [`FipsState::Unknown`] → always warns (never panics): absence of a probe
///   should not take down an application.
pub fn assert_fips_with(probe: &dyn FipsProbe, on_failure: OnFailure) -> FipsState {
    let state = probe.state();
    match state {
        FipsState::Enabled => {}
        FipsState::Disabled => match on_failure {
            OnFailure::Panic => panic!("cargo-fips-runtime: module is not in FIPS mode"),
            OnFailure::Warn => {
                eprintln!("cargo-fips-runtime: warning — module is not in FIPS mode")
            }
        },
        FipsState::Unknown => {
            eprintln!("cargo-fips-runtime: warning — FIPS state is unknown (no probe wired up)");
        }
    }
    state
}

/// Assert FIPS mode at startup.
///
/// - `assert_fips!()` uses [`NullProbe`] and [`OnFailure::Panic`].
/// - `assert_fips!(probe)` uses `probe` and [`OnFailure::Panic`].
/// - `assert_fips!(probe, on_failure)` uses both explicitly.
#[macro_export]
macro_rules! assert_fips {
    () => {
        $crate::assert_fips_with(&$crate::NullProbe, $crate::OnFailure::Panic)
    };
    ($probe:expr) => {
        $crate::assert_fips_with(&$probe, $crate::OnFailure::Panic)
    };
    ($probe:expr, $on_failure:expr) => {
        $crate::assert_fips_with(&$probe, $on_failure)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysEnabled;
    impl FipsProbe for AlwaysEnabled {
        fn state(&self) -> FipsState {
            FipsState::Enabled
        }
    }

    struct AlwaysDisabled;
    impl FipsProbe for AlwaysDisabled {
        fn state(&self) -> FipsState {
            FipsState::Disabled
        }
    }

    #[test]
    fn null_probe_is_unknown_and_does_not_panic() {
        let state = assert_fips_with(&NullProbe, OnFailure::Panic);
        assert_eq!(state, FipsState::Unknown);
    }

    #[test]
    fn enabled_probe_passes() {
        assert_eq!(
            assert_fips_with(&AlwaysEnabled, OnFailure::Panic),
            FipsState::Enabled
        );
    }

    #[test]
    fn disabled_probe_warns_without_panic() {
        assert_eq!(
            assert_fips_with(&AlwaysDisabled, OnFailure::Warn),
            FipsState::Disabled
        );
    }

    #[test]
    #[should_panic(expected = "not in FIPS mode")]
    fn disabled_probe_panics_on_failure() {
        let _ = assert_fips_with(&AlwaysDisabled, OnFailure::Panic);
    }

    #[test]
    fn macro_forms_compile() {
        let _ = assert_fips!();
        let _ = assert_fips!(NullProbe);
        let _ = assert_fips!(NullProbe, OnFailure::Warn);
    }
}

#[cfg(all(test, feature = "aws-lc-rs"))]
mod aws_lc_rs_tests {
    use super::*;

    #[test]
    fn probe_reports_a_concrete_state() {
        // Under the FIPS backend this is `Enabled`; regardless, a real probe must
        // never report `Unknown`.
        assert_ne!(AwsLcRsProbe.state(), FipsState::Unknown);
        assert_eq!(AwsLcRsProbe.identity().certificate.as_deref(), Some("4816"));
    }
}
