//! CycloneDX 1.6 CBOM generation (spec §11).
//!
//! Emits a Cryptography Bill of Materials: the validated module as a `library`
//! component carrying its CMVP facts, and each approved algorithm as a
//! `cryptographic-asset` component with crypto-properties (primitive,
//! parameters, `certificationLevel`, execution environment). Build provenance
//! goes in `metadata`.
//!
//! [`build_cbom`] is pure given a timestamp, so it is unit-testable. The exact
//! upstream CBOM JSON schema is large; this models it faithfully in spirit and
//! carries every field the spec requires. Strict schema validation against the
//! published CycloneDX schema is a follow-up.

use serde_json::{json, Map, Value};

/// One approved algorithm, already reduced from a registry entry.
#[derive(Debug, Clone)]
pub struct AlgorithmEntry {
    pub name: String,
    pub modes: Vec<String>,
    /// Derived descriptor: key sizes (`128/192/256`) or curves (`P-256, P-384`).
    pub parameter_set: Option<String>,
    pub cavp_certificate: Option<String>,
    pub oid: Option<String>,
}

/// Everything needed to render an attestation.
#[derive(Debug, Clone)]
pub struct AttestationInput {
    pub tool_version: String,
    pub project_name: Option<String>,
    pub project_version: Option<String>,
    pub module_id: String,
    pub vendor: String,
    pub declared_version: String,
    pub resolved_crate: Option<(String, String)>,
    pub cmvp_number: String,
    pub cmvp_status: String,
    pub security_level: u8,
    pub integrity_technique: String,
    pub target_triple: String,
    pub oe_classification: String,
    pub oe_description: Option<String>,
    pub algorithms: Vec<AlgorithmEntry>,
    /// Provenance properties (name, value), e.g. toolchain and git commit.
    pub provenance: Vec<(String, String)>,
    pub strictness: String,
}

/// FIPS 140-3 certification level enum value, e.g. `fips140-3-l1`.
fn cert_level_str(level: u8) -> String {
    format!("fips140-3-l{level}")
}

/// CycloneDX crypto `primitive` for a named algorithm.
fn primitive_for(name: &str) -> &'static str {
    let n = name.to_ascii_uppercase();
    if n.starts_with("AES") {
        "block-cipher"
    } else if n.starts_with("SHA") {
        "hash"
    } else if n.starts_with("HMAC") {
        "mac"
    } else if n.starts_with("ECDSA") || n.starts_with("RSA") || n.starts_with("EDDSA") {
        "signature"
    } else if n.starts_with("ECDH") || n.starts_with("KAS") {
        "key-agree"
    } else if n.starts_with("DRBG") || n.contains("RANDOM") {
        "drbg"
    } else {
        "other"
    }
}

/// CycloneDX `cryptoFunctions` for a primitive.
fn crypto_functions(primitive: &str) -> Vec<&'static str> {
    match primitive {
        "block-cipher" => vec!["encrypt", "decrypt"],
        "hash" => vec!["digest"],
        "mac" => vec!["tag", "verify"],
        "signature" => vec!["sign", "verify", "keygen"],
        "key-agree" => vec!["keygen"],
        "drbg" => vec!["generate"],
        _ => vec!["other"],
    }
}

/// Build the CycloneDX 1.6 CBOM document.
pub fn build_cbom(input: &AttestationInput, timestamp_secs: u64) -> Value {
    let timestamp = iso8601_utc(timestamp_secs);
    let serial = format!(
        "urn:uuid:{}",
        uuid_v4_like(
            timestamp_secs
                .wrapping_mul(0x9E3779B1)
                .wrapping_add(input.cmvp_number.len() as u64)
        )
    );
    let level = cert_level_str(input.security_level);

    // --- metadata ---
    let mut metadata = Map::new();
    metadata.insert("timestamp".into(), json!(timestamp));
    metadata.insert(
        "tools".into(),
        json!({ "components": [ { "type": "application", "name": "cargo-fips", "version": input.tool_version } ] }),
    );
    if let Some(name) = &input.project_name {
        let mut comp = Map::new();
        comp.insert("type".into(), json!("application"));
        comp.insert("name".into(), json!(name));
        if let Some(ver) = &input.project_version {
            comp.insert("version".into(), json!(ver));
        }
        metadata.insert("component".into(), Value::Object(comp));
    }
    let mut props: Vec<Value> = input
        .provenance
        .iter()
        .map(|(k, v)| json!({ "name": k, "value": v }))
        .collect();
    props.push(json!({ "name": "fips:strictness", "value": input.strictness }));
    props.push(json!({
        "name": "fips:assurance",
        "value": "evidence, not absolution: reflects no detected drift from the declared validated configuration; not a determination of FIPS compliance"
    }));
    metadata.insert("properties".into(), Value::Array(props));

    // --- module component ---
    let module_ref = format!("module:{}", input.module_id);
    let mut module_props = vec![
        json!({ "name": "cmvp:certificate", "value": input.cmvp_number }),
        json!({ "name": "cmvp:status", "value": input.cmvp_status }),
        json!({ "name": "cmvp:certificationLevel", "value": level }),
        json!({ "name": "fips:integrityTechnique", "value": input.integrity_technique }),
        json!({ "name": "fips:operatingEnvironment", "value": input.oe_description.clone().unwrap_or_else(|| input.target_triple.clone()) }),
        json!({ "name": "fips:operatingEnvironmentClassification", "value": input.oe_classification }),
        json!({ "name": "fips:targetTriple", "value": input.target_triple }),
        json!({ "name": "fips:declaredVersion", "value": input.declared_version }),
    ];
    if let Some((crate_name, crate_ver)) = &input.resolved_crate {
        module_props.push(
            json!({ "name": "fips:resolvedCrate", "value": format!("{crate_name} {crate_ver}") }),
        );
    }
    let module_component = json!({
        "type": "library",
        "bom-ref": module_ref,
        "name": input.module_id,
        "group": input.vendor,
        "version": input.declared_version,
        "properties": module_props,
    });

    // --- algorithm components ---
    let mut components = vec![module_component];
    let mut alg_refs: Vec<Value> = Vec::new();
    for alg in &input.algorithms {
        let primitive = primitive_for(&alg.name);
        let alg_ref = format!("crypto:{}", alg.name.to_ascii_lowercase());
        alg_refs.push(json!(alg_ref));

        let mut alg_props = Vec::new();
        alg_props.push(json!({
            "name": "cavp:certificate",
            "value": alg.cavp_certificate.clone().unwrap_or_else(|| "pending-transcription".to_string())
        }));
        if !alg.modes.is_empty() {
            alg_props.push(json!({ "name": "fips:modes", "value": alg.modes.join(", ") }));
        }

        let mut algorithm_properties = Map::new();
        algorithm_properties.insert("primitive".into(), json!(primitive));
        algorithm_properties.insert("executionEnvironment".into(), json!("software-plain-ram"));
        algorithm_properties.insert("certificationLevel".into(), json!([level]));
        algorithm_properties.insert("cryptoFunctions".into(), json!(crypto_functions(primitive)));
        if let Some(param) = &alg.parameter_set {
            algorithm_properties.insert("parameterSetIdentifier".into(), json!(param));
        }

        let mut crypto_properties = Map::new();
        crypto_properties.insert("assetType".into(), json!("algorithm"));
        crypto_properties.insert(
            "algorithmProperties".into(),
            Value::Object(algorithm_properties),
        );
        if let Some(oid) = &alg.oid {
            crypto_properties.insert("oid".into(), json!(oid));
        }

        components.push(json!({
            "type": "cryptographic-asset",
            "bom-ref": alg_ref,
            "name": alg.name,
            "cryptoProperties": Value::Object(crypto_properties),
            "properties": alg_props,
        }));
    }

    let dependencies = json!([ { "ref": module_ref, "dependsOn": alg_refs } ]);

    json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": 1,
        "metadata": Value::Object(metadata),
        "components": components,
        "dependencies": dependencies,
    })
}

/// Format UNIX seconds as ISO-8601 UTC (`YYYY-MM-DDThh:mm:ssZ`), no dependencies.
/// Uses Howard Hinnant's civil-from-days algorithm.
fn iso8601_utc(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let secs = unix_secs % 86_400;
    let (hh, mm, ss) = (secs / 3600, (secs % 3600) / 60, secs % 60);

    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// A format-valid (not cryptographically random) RFC-4122 v4 UUID, derived from
/// `seed` via splitmix64. Sufficient as a BOM serial number.
fn uuid_v4_like(seed: u64) -> String {
    let mut x = seed;
    let mut bytes = [0u8; 16];
    for chunk in bytes.chunks_mut(8) {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        chunk.copy_from_slice(&z.to_le_bytes());
    }
    bytes[6] = (bytes[6] & 0x0F) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3F) | 0x80; // variant
    let h = |b: u8| format!("{b:02x}");
    format!(
        "{}{}{}{}-{}{}-{}{}-{}{}-{}{}{}{}{}{}",
        h(bytes[0]),
        h(bytes[1]),
        h(bytes[2]),
        h(bytes[3]),
        h(bytes[4]),
        h(bytes[5]),
        h(bytes[6]),
        h(bytes[7]),
        h(bytes[8]),
        h(bytes[9]),
        h(bytes[10]),
        h(bytes[11]),
        h(bytes[12]),
        h(bytes[13]),
        h(bytes[14]),
        h(bytes[15]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AttestationInput {
        AttestationInput {
            tool_version: "0.0.1".into(),
            project_name: Some("demo".into()),
            project_version: Some("1.2.3".into()),
            module_id: "aws-lc-fips".into(),
            vendor: "Amazon Web Services Inc.".into(),
            declared_version: "AWS-LC-FIPS-2.0".into(),
            resolved_crate: Some(("aws-lc-fips-sys".into(), "0.13.14".into())),
            cmvp_number: "4816".into(),
            cmvp_status: "active".into(),
            security_level: 1,
            integrity_technique: "HMAC-SHA2-256".into(),
            target_triple: "x86_64-unknown-linux-gnu".into(),
            oe_classification: "tested".into(),
            oe_description: Some("Amazon Linux 2 (x86_64, Intel Xeon Platinum 8275CL)".into()),
            algorithms: vec![
                AlgorithmEntry {
                    name: "AES".into(),
                    modes: vec!["GCM".into(), "CBC".into()],
                    parameter_set: Some("128/192/256".into()),
                    cavp_certificate: None,
                    oid: None,
                },
                AlgorithmEntry {
                    name: "ECDSA".into(),
                    modes: vec!["SigGen".into()],
                    parameter_set: Some("P-256, P-384".into()),
                    cavp_certificate: None,
                    oid: Some("1.2.840.10045.4.3.2".into()),
                },
            ],
            provenance: vec![("build:target".into(), "x86_64-unknown-linux-gnu".into())],
            strictness: "tested-only".into(),
        }
    }

    #[test]
    fn header_fields() {
        let v = build_cbom(&sample(), 1_750_000_000);
        assert_eq!(
            v["$schema"],
            "http://cyclonedx.org/schema/bom-1.6.schema.json"
        );
        assert_eq!(v["bomFormat"], "CycloneDX");
        assert_eq!(v["specVersion"], "1.6");
        assert!(v["serialNumber"].as_str().unwrap().starts_with("urn:uuid:"));
        assert_eq!(v["version"], 1);
    }

    #[test]
    fn module_plus_algorithm_components() {
        let v = build_cbom(&sample(), 1_750_000_000);
        let comps = v["components"].as_array().unwrap();
        assert_eq!(comps.len(), 3); // module + 2 algorithms
        assert_eq!(comps[0]["type"], "library");
        assert_eq!(comps[1]["type"], "cryptographic-asset");
        assert_eq!(comps[1]["cryptoProperties"]["assetType"], "algorithm");
        assert_eq!(
            comps[1]["cryptoProperties"]["algorithmProperties"]["certificationLevel"][0],
            "fips140-3-l1"
        );
    }

    #[test]
    fn primitive_mapping() {
        assert_eq!(primitive_for("AES"), "block-cipher");
        assert_eq!(primitive_for("SHA2"), "hash");
        assert_eq!(primitive_for("HMAC"), "mac");
        assert_eq!(primitive_for("ECDSA"), "signature");
    }

    #[test]
    fn iso8601_is_correct() {
        // 1_750_000_000 = 2025-06-15T15:06:40Z
        assert_eq!(iso8601_utc(1_750_000_000), "2025-06-15T15:06:40Z");
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn uuid_is_v4_shaped() {
        let u = uuid_v4_like(12345);
        assert_eq!(u.len(), 36);
        let parts: Vec<&str> = u.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert_eq!(&parts[2][0..1], "4"); // version nibble
    }
}
