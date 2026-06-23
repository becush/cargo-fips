//! Runtime companion for `cargo-fips` (spec §10.5).
//!
//! `cargo fips check` proves a build *was configured* for FIPS. But FIPS is also
//! a *runtime* property: the loaded module must report FIPS mode active and its
//! power-on self-test (POST) must have passed. This crate is the small library
//! a downstream application links to assert that at startup and to record module
//! identity and service-indicator status.
//!
//! [`FipsProbe`] is the common abstraction over each provider's own runtime FIPS
//! query (`OsslContext::fips_is_enabled()`, `try_fips_mode()`, a rustls
//! `CryptoProvider::fips()`), so an application wires in whichever it already has.
//!
//! # Probes
//!
//! - [`NullProbe`] (always available) reports [`FipsState::Unknown`] — the
//!   dependency-free default.
//! - [`AwsLcRsProbe`] (behind the `aws-lc-rs` feature) calls
//!   `aws_lc_rs::try_fips_mode()` to report the live state of the linked AWS-LC
//!   module (CMVP certificate #4816).
//! - [`OpenSslProbe`] consumes a provider's runtime FIPS status (e.g.
//!   rustls-ossl's `OsslContext::fips_is_enabled()` or a rustls
//!   `CryptoProvider::fips()`); OpenSSL FIPS mode is decided dynamically at
//!   process start, not at build time (cert #4857).
//!
//! Other backends implement [`FipsProbe`] the same way, each forwarding its own
//! provider's runtime FIPS query.
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
//!
//! # Reporting
//!
//! The same probe feeds existing operational surfaces:
//!
//! - [`readiness`] turns a probe into a fail-closed readiness decision to wire
//!   into a service's `/healthz` probe (enforcement): the orchestrator drains
//!   traffic from any instance that cannot prove FIPS is active.
//! - [`record`] (behind the `tracing` feature) emits a structured startup event
//!   into the application's existing `tracing` subscriber (evidence): a
//!   timestamped audit record, with severity tracking the state.
//!
//! Both are startup/sampled views, because OpenSSL FIPS mode is effectively a
//! startup property that holds for the life of the process. There is deliberately
//! no continuous gauge: a FIPS self-test failure puts the module into a hard error
//! state that takes the process down, so ordinary crash alerting already covers
//! it. The state actually worth catching is the silent one, an app that comes up
//! without the FIPS provider and quietly runs non-FIPS crypto, which is exactly
//! what [`readiness`] and a runtime status query like `fips_is_enabled()` catch.

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

/// A [`FipsProbe`] for the OpenSSL 3 FIPS provider (e.g. CMVP certificate #4857).
///
/// For OpenSSL, FIPS mode is **dynamic**, decided at process start by which
/// providers are loaded and whether the default property query enforces
/// `fips=yes`. There is no build-time fact to read, so this probe takes the
/// answer as input rather than linking an OpenSSL binding itself: feed it the
/// runtime status from whatever binding the application already uses. With
/// rustls-ossl that is `OsslContext::fips_is_enabled()`; you can equally pass a
/// rustls `CryptoProvider::fips()` or your own
/// `EVP_default_properties_is_fips_enabled` + `OSSL_PROVIDER_available(.., "fips")`
/// check. `None` means "could not determine", giving [`FipsState::Unknown`].
///
/// The probe only *reads* status. Forcing the mode (e.g. rustls-ossl's
/// `enforce_fips()`) is the application's call, kept separate on purpose: this
/// crate observes and reports, it does not configure the module.
///
/// ```
/// use cargo_fips_runtime::{FipsProbe, FipsState, OpenSslProbe};
///
/// // e.g. OpenSslProbe::from_status(Some(ctx.fips_is_enabled()))
/// assert_eq!(OpenSslProbe::from_status(Some(true)).state(), FipsState::Enabled);
/// assert_eq!(OpenSslProbe::from_status(None).state(), FipsState::Unknown);
/// ```
pub struct OpenSslProbe {
    fips_active: Option<bool>,
}

impl OpenSslProbe {
    /// Build from a provider-supplied runtime FIPS status (`None` = unknown).
    pub fn from_status(fips_active: Option<bool>) -> Self {
        Self { fips_active }
    }
}

impl FipsProbe for OpenSslProbe {
    fn state(&self) -> FipsState {
        match self.fips_active {
            Some(true) => FipsState::Enabled,
            Some(false) => FipsState::Disabled,
            None => FipsState::Unknown,
        }
    }

    fn identity(&self) -> ModuleReport {
        ModuleReport {
            module: Some("rhel9-openssl-fips".to_string()),
            version: None,
            certificate: Some("4857".to_string()),
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

/// Outcome of a fail-closed readiness check.
///
/// Returned by [`readiness`] for wiring a `FipsProbe` into a service's
/// readiness/`/healthz` endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readiness {
    /// Whether the service should accept traffic. `true` only when FIPS is
    /// provably active.
    pub ready: bool,
    /// The observed state behind the decision.
    pub state: FipsState,
    /// Human-readable reason, suitable for a health-check response body.
    pub detail: String,
}

/// Fail-closed FIPS readiness, for an orchestrated `/healthz`/readiness probe.
///
/// Unlike [`assert_fips_with`] (which only *warns* on [`FipsState::Unknown`] so
/// a missing probe never crashes a process), this gate is strict: it is
/// `ready` **only** when the module reports [`FipsState::Enabled`]. Both
/// [`FipsState::Disabled`] and [`FipsState::Unknown`] are not-ready, so an
/// orchestrator drains traffic from any instance that cannot *prove* FIPS is
/// active — enforcement, not just logging.
///
/// ```
/// use cargo_fips_runtime::{readiness, NullProbe, OpenSslProbe};
///
/// // No probe wired up → fail closed.
/// assert!(!readiness(&NullProbe).ready);
///
/// // Provider reports FIPS active → ready.
/// assert!(readiness(&OpenSslProbe::from_status(Some(true))).ready);
/// ```
///
/// Mapping it onto an HTTP probe (framework-agnostic — no web dep is pulled in):
///
/// ```ignore
/// async fn healthz() -> (StatusCode, String) {
///     let r = readiness(&OpenSslProbe::from_status(Some(ctx.fips_is_enabled())));
///     let code = if r.ready { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
///     (code, r.detail)
/// }
/// ```
pub fn readiness(probe: &dyn FipsProbe) -> Readiness {
    let state = probe.state();
    let detail = match state {
        FipsState::Enabled => "fips: active".to_string(),
        FipsState::Disabled => "fips: module loaded but NOT operating in FIPS mode".to_string(),
        FipsState::Unknown => "fips: state could not be determined".to_string(),
    };
    Readiness {
        ready: matches!(state, FipsState::Enabled),
        state,
        detail,
    }
}

/// Emit the runtime FIPS status into the [`tracing`] pipeline as a structured
/// event (available with the `tracing` feature).
///
/// This is the audit-trail companion to [`assert_fips_with`]: call it once at
/// startup to land a timestamped, structured record (module, certificate, and
/// observed state) in whatever subscriber the application already runs. Severity
/// tracks the state (`info` when enabled, `warn` when unknown, `error` when the
/// module is loaded but not in FIPS mode), so existing log-based alerting can key
/// off it without a new metrics pipeline.
///
/// FIPS mode is effectively a startup property that holds for the life of the
/// process, so this is a boot-time record rather than a continuous monitor. There
/// isn't a soft runtime signal to add either: a self-test failure puts the module
/// into a hard error state that crashes the process, which ordinary crash alerting
/// already catches.
#[cfg(feature = "tracing")]
pub fn record(probe: &dyn FipsProbe) {
    let report = probe.identity();
    let module = report.module.as_deref().unwrap_or("unknown");
    let certificate = report.certificate.as_deref().unwrap_or("unknown");
    match report.state {
        FipsState::Enabled => tracing::info!(
            target: "cargo_fips",
            module,
            certificate,
            state = %report.state,
            "fips module active"
        ),
        FipsState::Disabled => tracing::error!(
            target: "cargo_fips",
            module,
            certificate,
            state = %report.state,
            "fips module loaded but NOT operating in FIPS mode"
        ),
        FipsState::Unknown => tracing::warn!(
            target: "cargo_fips",
            module,
            certificate,
            state = %report.state,
            "fips state could not be determined"
        ),
    }
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

    #[test]
    fn openssl_probe_maps_status() {
        assert_eq!(
            OpenSslProbe::from_status(Some(true)).state(),
            FipsState::Enabled
        );
        assert_eq!(
            OpenSslProbe::from_status(Some(false)).state(),
            FipsState::Disabled
        );
        assert_eq!(OpenSslProbe::from_status(None).state(), FipsState::Unknown);
        assert_eq!(
            OpenSslProbe::from_status(Some(true))
                .identity()
                .certificate
                .as_deref(),
            Some("4857")
        );
    }

    #[test]
    fn readiness_is_fail_closed() {
        assert!(readiness(&AlwaysEnabled).ready);
        // Both Disabled and Unknown must fail closed.
        assert!(!readiness(&AlwaysDisabled).ready);
        let unknown = readiness(&NullProbe);
        assert!(!unknown.ready);
        assert_eq!(unknown.state, FipsState::Unknown);
        assert!(!unknown.detail.is_empty());
    }

    #[cfg(feature = "tracing")]
    #[test]
    fn record_does_not_panic() {
        // With no subscriber installed the events are dropped; the call must
        // still be infallible.
        record(&NullProbe);
        record(&AlwaysEnabled);
        record(&AlwaysDisabled);
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
