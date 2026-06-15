//! Optional signing of the attestation via the `cosign` binary (spec §10.4).
//!
//! Per the project's "delegate, don't reinvent" principle, signing is delegated
//! to cosign — the reference Sigstore tool — rather than reimplemented. Two
//! modes:
//!
//! - **key-based** (`[attest] cosign_key` / `--cosign-key`): offline detached
//!   signature, no transparency-log upload;
//! - **keyless** (no key): Sigstore/Fulcio + Rekor, producing a signature,
//!   certificate, and bundle (requires ambient OIDC, e.g. in CI).

use std::path::{Path, PathBuf};
use std::process::Command;

/// A signing failure (cosign missing, or a non-zero exit).
#[derive(Debug)]
pub struct SignError(pub String);

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Artifacts produced by signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignOutputs {
    pub signature: PathBuf,
    pub certificate: Option<PathBuf>,
    pub bundle: Option<PathBuf>,
}

impl SignOutputs {
    /// Comma-separated list of produced artifact paths.
    pub fn describe(&self) -> String {
        let mut parts = vec![self.signature.display().to_string()];
        if let Some(cert) = &self.certificate {
            parts.push(cert.display().to_string());
        }
        if let Some(bundle) = &self.bundle {
            parts.push(bundle.display().to_string());
        }
        parts.join(", ")
    }
}

/// Build the `cosign sign-blob` argument vector (pure; unit-tested).
pub fn sign_blob_args(
    cbom: &Path,
    key: Option<&Path>,
    signature: &Path,
    certificate: Option<&Path>,
    bundle: Option<&Path>,
) -> Vec<String> {
    let mut args = vec!["sign-blob".to_string(), "--yes".to_string()];
    if let Some(key) = key {
        // Key-based, offline: don't upload to the transparency log.
        args.push("--key".to_string());
        args.push(key.display().to_string());
        args.push("--tlog-upload=false".to_string());
    }
    args.push("--output-signature".to_string());
    args.push(signature.display().to_string());
    if let Some(cert) = certificate {
        args.push("--output-certificate".to_string());
        args.push(cert.display().to_string());
    }
    if let Some(bundle) = bundle {
        args.push("--bundle".to_string());
        args.push(bundle.display().to_string());
    }
    args.push(cbom.display().to_string());
    args
}

/// Sign `cbom` with cosign. Uses key-based signing when `key` is `Some`,
/// otherwise keyless. The cosign binary is `$COSIGN` or `cosign` on `PATH`.
pub fn cosign_sign(cbom: &Path, key: Option<&Path>) -> Result<SignOutputs, SignError> {
    let bin = std::env::var("COSIGN").unwrap_or_else(|_| "cosign".to_string());

    let signature = with_suffix(cbom, ".sig");
    let (certificate, bundle) = if key.is_some() {
        (None, None)
    } else {
        (Some(with_suffix(cbom, ".pem")), Some(with_suffix(cbom, ".bundle")))
    };

    let args = sign_blob_args(
        cbom,
        key,
        &signature,
        certificate.as_deref(),
        bundle.as_deref(),
    );

    let output = Command::new(&bin).args(&args).output().map_err(|err| {
        SignError(format!(
            "could not run `{bin}` (is cosign installed and on PATH?): {err}"
        ))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SignError(format!("cosign exited non-zero: {}", stderr.trim())));
    }

    Ok(SignOutputs {
        signature,
        certificate,
        bundle,
    })
}

/// Append a suffix to a path's file name (`a.json` + `.sig` -> `a.json.sig`),
/// preserving the existing extension (unlike `set_extension`).
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_based_args_are_offline() {
        let args = sign_blob_args(
            Path::new("b.cdx.json"),
            Some(Path::new("cosign.key")),
            Path::new("b.cdx.json.sig"),
            None,
            None,
        );
        assert_eq!(args[0], "sign-blob");
        assert!(args.iter().any(|a| a == "--key"));
        assert!(args.iter().any(|a| a == "cosign.key"));
        assert!(args.iter().any(|a| a == "--tlog-upload=false"));
        assert_eq!(args.last().unwrap(), "b.cdx.json");
    }

    #[test]
    fn keyless_args_request_cert_and_bundle() {
        let args = sign_blob_args(
            Path::new("b.cdx.json"),
            None,
            Path::new("b.cdx.json.sig"),
            Some(Path::new("b.cdx.json.pem")),
            Some(Path::new("b.cdx.json.bundle")),
        );
        assert!(!args.iter().any(|a| a == "--key"));
        assert!(args.iter().any(|a| a == "--output-certificate"));
        assert!(args.iter().any(|a| a == "--bundle"));
    }

    #[test]
    fn with_suffix_preserves_extension() {
        assert_eq!(
            with_suffix(Path::new("target/x.cdx.json"), ".sig"),
            PathBuf::from("target/x.cdx.json.sig")
        );
    }
}
